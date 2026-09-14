//go:build windows

package scwindows

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Like every other test in this package, these can only RUN on a Windows host
// and CI does not yet have one (see iphlp_test.go). GOOS=windows go vet
// compiles them and go test -c proves they link; neither proves an assertion
// has ever passed.
//
// What IS pinned here is the only part of userhive.go that needs no machine
// state: the DECISION about which hive to use. It is behind hiveFacts precisely
// so that the three questions it asks — am I elevated, who am I, who is at the
// console — can be answered by a table instead of by a second user account, an
// elevated shell and a physical console. Getting that decision wrong in the
// permissive direction is what this whole file exists to prevent, so the cases
// below spend most of their weight on the failure paths.

// answerBool and answerSID build the fixed hiveFacts members a case describes.
// They also record whether they were CALLED, which is how the not-elevated
// case can assert that no session lookup happens at all.
type answerBool struct {
	v      bool
	err    error
	called int
}

func (a *answerBool) fn() func() (bool, error) {
	return func() (bool, error) { a.called++; return a.v, a.err }
}

type answerSID struct {
	v      string
	err    error
	called int
}

func (a *answerSID) fn() func() (string, error) {
	return func() (string, error) { a.called++; return a.v, a.err }
}

// Two SIDs that differ the way a real standard-user/administrator pair does:
// same domain prefix, different RID.
const (
	sidInteractive = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	sidAdmin       = "S-1-5-21-1111111111-2222222222-3333333333-500"
)

func TestChooseUserHive(t *testing.T) {
	boom := errors.New("boom")

	cases := []struct {
		name string

		elevated    bool
		elevatedErr error
		mine        string
		mineErr     error
		theirs      string
		theirsErr   error

		wantInteractive bool
		wantSID         string
		wantErr         bool
	}{
		{
			// The normal proxy-mode installation: a logon task running as the
			// interactive user. HKCU is theirs; nothing else is consulted.
			name:   "not elevated uses HKEY_CURRENT_USER",
			mine:   sidInteractive,
			theirs: sidInteractive,
		},
		{
			// The single-account machine: UAC asked for consent, so the
			// elevated token is the same user's.
			name:     "elevated as the interactive user uses HKEY_CURRENT_USER",
			elevated: true,
			mine:     sidInteractive,
			theirs:   sidInteractive,
		},
		{
			name:     "a SID that differs only in case is still the same user",
			elevated: true,
			mine:     "s-1-5-21-1111111111-2222222222-3333333333-1001",
			theirs:   sidInteractive,
		},
		{
			// The enterprise-default machine, and the entire point of the
			// file: UAC asked for the administrator's credentials.
			name:            "elevated as a different account uses the interactive user's hive",
			elevated:        true,
			mine:            sidAdmin,
			theirs:          sidInteractive,
			wantInteractive: true,
			wantSID:         sidInteractive,
		},
		{
			// The defect windows.Token.IsElevated would have introduced: a
			// failed elevation query must NOT read as "not elevated", because
			// that answer silently selects HKCU.
			name:        "an unanswerable elevation check refuses",
			elevatedErr: boom,
			mine:        sidAdmin,
			theirs:      sidInteractive,
			wantErr:     true,
		},
		{
			name:     "an unanswerable console user refuses rather than using HKCU",
			elevated: true,
			mine:     sidAdmin,
			// WTSQueryUserToken without SE_TCB_NAME, and the session-owner
			// route failed too.
			theirsErr: boom,
			wantErr:   true,
		},
		{
			name:     "an unanswerable own account refuses rather than using HKCU",
			elevated: true,
			mineErr:  boom,
			theirs:   sidInteractive,
			wantErr:  true,
		},
		{
			// windows.SID.String() returns "" when the conversion fails, so an
			// empty SID is a FAILED read wearing a plausible value. Accepting
			// it would build the hive path `HKU\` + `\Software\...`.
			name:     "an empty console SID refuses rather than naming no hive",
			elevated: true,
			mine:     sidAdmin,
			theirs:   "",
			wantErr:  true,
		},
		{
			name:     "an empty own SID refuses rather than comparing nothing",
			elevated: true,
			mine:     "",
			theirs:   sidInteractive,
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			elev := &answerBool{v: tc.elevated, err: tc.elevatedErr}
			mine := &answerSID{v: tc.mine, err: tc.mineErr}
			theirs := &answerSID{v: tc.theirs, err: tc.theirsErr}

			got, err := chooseUserHive(hiveFacts{
				elevated:        elev.fn(),
				processUser:     mine.fn(),
				interactiveUser: theirs.fn(),
			})

			if tc.wantErr {
				if err == nil {
					t.Fatalf("chooseUserHive = %+v, want an error", got)
				}
				// The refusal must not ALSO look like a usable answer: a
				// caller that ignored the error and used the target would be
				// back to writing the administrator's hive.
				if got.Interactive || got.SID != "" {
					t.Errorf("chooseUserHive returned an error AND a target %+v; the target must be empty", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("chooseUserHive: %v", err)
			}
			if got.Interactive != tc.wantInteractive {
				t.Errorf("Interactive = %v, want %v", got.Interactive, tc.wantInteractive)
			}
			if got.SID != tc.wantSID {
				t.Errorf("SID = %q, want %q", got.SID, tc.wantSID)
			}
		})
	}
}

// TestChooseUserHiveSkipsTheSessionLookupWhenNotElevated pins the ordering, not
// just the answer. An unelevated dpb is the supported proxy-mode installation
// (cliapp/service_task_windows.go runs it as a logon task), and making that
// path depend on WTSQueryUserToken or a name-to-SID lookup would let the common
// case start failing for a reason that cannot possibly apply to it.
func TestChooseUserHiveSkipsTheSessionLookupWhenNotElevated(t *testing.T) {
	elev := &answerBool{v: false}
	mine := &answerSID{v: sidInteractive}
	theirs := &answerSID{err: errors.New("must not be called")}

	got, err := chooseUserHive(hiveFacts{
		elevated:        elev.fn(),
		processUser:     mine.fn(),
		interactiveUser: theirs.fn(),
	})
	if err != nil {
		t.Fatalf("chooseUserHive: %v", err)
	}
	if got.Interactive {
		t.Errorf("Interactive = true, want HKEY_CURRENT_USER")
	}
	if elev.called != 1 {
		t.Errorf("elevated called %d times, want 1", elev.called)
	}
	if theirs.called != 0 {
		t.Errorf("interactiveUser called %d times, want 0", theirs.called)
	}
}

// TestUserHivePathAndLabel pins the two string builders every registry call in
// proxy.go and env.go goes through. A missing separator here does not fail to
// compile: it opens `S-1-5-...Software\Microsoft\...`, which simply does not
// exist, turning a working configuration into a puzzling not-found.
func TestUserHivePathAndLabel(t *testing.T) {
	if got := currentUserHive.path(environmentKey); got != environmentKey {
		t.Errorf("currentUserHive.path = %q, want %q", got, environmentKey)
	}
	if !currentUserHive.isCurrentUser() {
		t.Error("currentUserHive.isCurrentUser = false")
	}
	if currentUserHive.root != registry.CURRENT_USER {
		t.Errorf("currentUserHive.root = %v, want registry.CURRENT_USER", currentUserHive.root)
	}
	if got, want := currentUserHive.label(environmentKey), `HKCU\Environment`; got != want {
		t.Errorf("currentUserHive.label = %q, want %q", got, want)
	}

	h := userHive{root: registry.USERS, prefix: sidInteractive + `\`, name: `HKU\` + sidInteractive}
	if h.isCurrentUser() {
		t.Error("an HKEY_USERS hive reported isCurrentUser = true, which would send Live to WinHTTP for the wrong token")
	}
	if got, want := h.path(environmentKey), sidInteractive+`\`+environmentKey; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	if got, want := h.label(environmentKey), `HKU\`+sidInteractive+`\Environment`; got != want {
		t.Errorf("label = %q, want %q", got, want)
	}
}

// TestGateOnProxyEnable pins the one bit Live takes from the hive rather than
// from WinHTTP. See gateOnProxyEnable for why the previous assumption —
// "WinHTTP nulls lpszProxy when ProxyEnable is 0" — is folklore MSDN never
// states, and why this may only ever subtract.
func TestGateOnProxyEnable(t *testing.T) {
	const list = "http=127.0.0.1:8080;https=127.0.0.1:8080"
	if got := gateOnProxyEnable(list, true); got != list {
		t.Errorf("gateOnProxyEnable(enabled) = %q, want it passed through unchanged", got)
	}
	if got := gateOnProxyEnable(list, false); got != "" {
		t.Errorf("gateOnProxyEnable(disabled) = %q, want %q", got, "")
	}
	// The disabled case must reach proxyStateFromIE as "no proxy at all", not
	// as a proxy with the Enable keys flipped by hand somewhere else.
	st := proxyStateFromIE(false, "", gateOnProxyEnable(list, false), "")
	for _, k := range []string{"HTTPEnable", "HTTPSEnable", "SOCKSEnable"} {
		if got := st.Keys[k]; got != "0" {
			t.Errorf("%s = %q with ProxyEnable = 0, want %q", k, got, "0")
		}
	}
	for _, k := range []string{"HTTPProxy", "HTTPPort", "HTTPSProxy", "HTTPSPort"} {
		if got, ok := st.Keys[k]; ok {
			t.Errorf("%s = %q with ProxyEnable = 0, want the key absent", k, got)
		}
	}
}

// TestWithoutAutoDiscoveryDropsOnlyTheUnobservableKey. liveFromHive cannot read
// the WPAD bit — it lives inside the binary DefaultConnectionSettings blob —
// so it must publish nothing rather than a "0" that reads as a definite no.
func TestWithoutAutoDiscoveryDropsOnlyTheUnobservableKey(t *testing.T) {
	st := withoutAutoDiscovery(proxyStateFromIE(false, "http://pac.example/p.pac", "http=a.example:1", ""))
	if v, ok := st.Keys[keyAutoDiscoveryEnable]; ok {
		t.Errorf("%s = %q, want the key absent", keyAutoDiscoveryEnable, v)
	}
	// Everything the registry CAN answer survives.
	for k, want := range map[string]string{
		keyAutoConfigEnable: "1",
		keyAutoConfigURL:    "http://pac.example/p.pac",
		"HTTPEnable":        "1",
		"HTTPProxy":         "a.example",
		"HTTPPort":          "1",
	} {
		if got := st.Keys[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

// TestWTSInfoClassOrdinals pins the two WTS_INFO_CLASS members
// consoleUserSIDFromSessionOwner asks for. wtsapi32.h declares the enumeration
// with no explicit values, so these are positions in a list — and a wrong
// number does not fail, it answers a DIFFERENT question: 4 is WTSSessionId, a
// ULONG that read as a string is four bytes with no terminator, and 6 is
// WTSWinStationName, which would be looked up as an account name.
func TestWTSInfoClassOrdinals(t *testing.T) {
	if wtsUserName != 5 {
		t.Errorf("wtsUserName = %d, want 5 (WTSInitialProgram=0, ..., WTSSessionId=4, WTSUserName=5)", wtsUserName)
	}
	if wtsDomainName != 7 {
		t.Errorf("wtsDomainName = %d, want 7 (..., WTSWinStationName=6, WTSDomainName=7)", wtsDomainName)
	}
	if noConsoleSession != 0xFFFFFFFF {
		t.Errorf("noConsoleSession = %#x, want 0xFFFFFFFF", uint32(noConsoleSession))
	}
	if wtsCurrentServerHandle != windows.Handle(0) {
		t.Errorf("wtsCurrentServerHandle = %v, want 0 (WTS_CURRENT_SERVER_HANDLE)", wtsCurrentServerHandle)
	}
}

// TestWTSQuerySessionInformationResolves is the same cheapest-possible guard
// iphlp_test.go applies to the thirteen procedures that file wraps. This
// procedure lives in userhive.go rather than iphlp.go (see the comment beside
// it there), so its resolve check lives here rather than being the one
// unpinned procedure in the package.
func TestWTSQuerySessionInformationResolves(t *testing.T) {
	if err := procWTSQuerySessionInformationW.Find(); err != nil {
		t.Errorf("WTSQuerySessionInformationW: does not resolve: %v", err)
	}
}
