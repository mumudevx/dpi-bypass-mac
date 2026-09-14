//go:build windows

package scwindows

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// This file answers one question for proxy.go and env.go: WHICH USER'S
// registry hive are the per-user settings supposed to go into?
//
// # The bug it exists to fix
//
// registry.CURRENT_USER is not "the person at the keyboard". MSDN, "Predefined
// Keys", HKEY_CURRENT_USER: "The mapping between HKEY_CURRENT_USER and
// HKEY_USERS is per process and is established the first time the process
// references HKEY_CURRENT_USER. The mapping is based on the security context
// of the first thread to reference HKEY_CURRENT_USER. If this security context
// does not have a registry hive loaded in HKEY_USERS, the mapping is
// established with HKEY_USERS\.Default. After this mapping is established it
// persists, even if the security context of the thread changes."
// https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys
//
// dpb needs elevation on Windows. On the enterprise-default machine — a
// standard user account plus a SEPARATE administrator account, where the UAC
// prompt asks for the admin's CREDENTIALS rather than for consent — the
// elevated process runs as the ADMIN, so HKCU is the admin's hive. Before this
// file existed, SetManual wrote the admin's Internet Settings, Live read the
// same token's configuration back through WinHTTP, Verify passed, and the
// interactive user's browser was never proxied at all. dpb reported Ready
// while changing nothing anyone could see. That is the failure class
// windows.go's Contract 1 exists to catch, and it slipped through precisely
// because BOTH halves were looking at the same wrong place.
//
// The same paragraph names a second, quieter version of it: a LocalSystem
// service whose account has no hive loaded gets HKEY_USERS\.Default, so the
// writes land in the template for future new users. Also a silent success.
//
// # What this file does instead
//
// resolveUserHive picks a registry ROOT — either registry.CURRENT_USER or
// HKEY_USERS\<SID> for the user logged on at the physical console — and every
// per-user read and write in proxy.go and env.go is opened relative to it.
//
// # Why HKEY_USERS\<SID> and not RegOpenCurrentUser
//
// MSDN's own advice on the page quoted above is "This handle should not be
// used in a service or an application that impersonates different users.
// Instead, call the RegOpenCurrentUser function." RegOpenCurrentUser resolves
// against the CALLING THREAD'S token, so using it means impersonating the
// interactive user for the duration — and impersonation is per-THREAD, which
// in Go means runtime.LockOSThread, a token that must be duplicated to an
// impersonation token first, and a RevertToSelf whose failure leaves a
// poisoned OS thread behind. Worse, it is unavailable in the case that matters
// most: an elevated administrator does NOT hold SE_TCB_NAME, so it cannot
// obtain the interactive user's token to impersonate in the first place (see
// interactiveUserSID).
//
// Addressing the hive by SID needs no impersonation, no thread affinity and no
// token at all once the SID is known, and Internet Settings and Environment
// both live directly under HKEY_USERS\<SID> — neither is part of the
// HKCU\Software\Classes merge that HKEY_USERS\<SID> would miss.
//
// # The rule when it cannot be worked out
//
// It REFUSES. It never falls back to CURRENT_USER after a failed lookup. This
// project has paid for the opposite reflex twice, both times caught in review
// rather than production: a ProcessStart that reported "dead" whenever it
// could not query a process would have made Replay tear down a RUNNING user's
// proxy, DNS and routes, and an envCtl.Get that read a failed read as "unset"
// would have made Revert DELETE a user's pre-existing HTTPS_PROXY instead of
// restoring it. Writing a proxy setting into the wrong hive is the same class
// of lie: it reports success for something that did not happen.

// userHive is the registry root every per-user setting in this package is
// opened relative to, plus the name to print when something under it fails.
//
// It holds no handle. registry.CURRENT_USER and registry.USERS are both
// PREDEFINED keys — MSDN: "The system defines predefined keys that are always
// open" — so a userHive is a plain value with nothing to close and no lifetime
// to get wrong. The interactive case carries the SID as a PATH PREFIX rather
// than as an opened HKEY_USERS\<SID> handle for the same reason: it removes
// the question of what access rights the parent handle needed, because every
// access check then happens on the key actually being opened.
type userHive struct {
	// root is registry.CURRENT_USER or registry.USERS.
	root registry.Key
	// prefix is "" for CURRENT_USER and `<SID>\` for HKEY_USERS.
	prefix string
	// name is "HKCU" or `HKU\<SID>`, for error messages only.
	name string
}

// isCurrentUser reports whether this hive is the calling process's own HKCU.
//
// Live reads it to decide whether WinHTTP can answer for this user at all; see
// proxyCtl.Live.
func (h userHive) isCurrentUser() bool { return h.prefix == "" }

// path turns a hive-relative key path into one that can be opened under root.
func (h userHive) path(sub string) string { return h.prefix + sub }

// label spells a hive-relative key path the way a user should see it in an
// error. Errors in this package name a registry location the reader can go and
// look at, and "HKCU\..." would be a lie in the interactive case — that is the
// whole failure this file fixes, and an error message that repeated it would
// send someone to the wrong hive with regedit open.
func (h userHive) label(sub string) string { return h.name + `\` + sub }

// sid is the SID this hive is addressed by, or "" for CURRENT_USER.
func (h userHive) sid() string { return strings.TrimSuffix(h.prefix, `\`) }

// requireLoaded re-proves that the hive this value names is still loaded.
//
// # Why a pinned hive is not enough
//
// resolveUserHive probes HKEY_USERS\<SID> once, before returning, and its
// comment explains what that probe is for: registry.CreateKey MATERIALISES
// every missing key in the path it is given, so without the probe a write
// aimed at `HKU\<SID>\Software\...` would invent the <SID> root itself and
// every subsequent write would succeed into a phantom hive nothing reads.
//
// The probe is a point-in-time answer, and (p *port).userHive PINS the result
// for the rest of the port's life — deliberately, so that a capture and its
// revert always address the same hive. That pinning comment used to promise
// that a hive which unloads in between "makes the HKU\<SID> path fail to open
// — a loud error on the revert". That was true of every OpenKey reader in this
// package and FALSE of its two CreateKey writers, which would have re-created
// the whole branch instead:
//
//	an elevated admin plus a separate signed-in user; dpb applies proxy mode;
//	the user signs out or fast-user-switches, unloading their hive; Ctrl-C
//	teardown calls Restore, which re-creates HKU\<SID>\...\Internet Settings
//	as a phantom key, writes ProxyEnable=0 into it, and reports a clean revert
//	of a machine it did not touch.
//
// So every writer calls this first, and the promise the pinning comment makes
// is now kept by code rather than by assumption.
//
// CURRENT_USER needs no probe: it is a predefined key the system keeps open
// for this process's own token (see userHive), and it cannot go away while the
// process that is asking still exists.
func (h userHive) requireLoaded() error {
	if h.isCurrentUser() {
		return nil
	}
	// QUERY_VALUE only, the least access that proves existence — the same
	// probe, spelled the same way, as resolveUserHive's.
	root, err := registry.OpenKey(h.root, h.sid(), registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("netstate: %s is no longer a loaded registry hive, so nothing can be written to it "+
			"(that user has signed out or switched away since dpb captured their settings): %w", h.name, err)
	}
	// Closed immediately for the reason resolveUserHive gives: this was an
	// existence probe, not the handle the caller uses.
	_ = root.Close()
	return nil
}

// createKey opens a hive-relative subkey for writing, creating what is
// missing — but only after requireLoaded has proved there is a hive to create
// it in. It is the only way anything in this package may call
// registry.CreateKey under a userHive; see requireLoaded for what a bare
// CreateKey does to an unloaded hive.
func (h userHive) createKey(sub string, access uint32) (registry.Key, error) {
	if err := h.requireLoaded(); err != nil {
		return 0, err
	}
	key, _, err := registry.CreateKey(h.root, h.path(sub), access)
	if err != nil {
		return 0, fmt.Errorf("netstate: open %s for writing: %w", h.label(sub), err)
	}
	return key, nil
}

// currentUserHive is the ordinary answer: this process's own HKCU.
var currentUserHive = userHive{root: registry.CURRENT_USER, name: "HKCU"}

// hiveTarget is chooseUserHive's decision, before any registry handle exists.
// Keeping the DECISION separate from the registry work is what makes it
// table-testable (see userhive_test.go) without a Windows machine, a console
// session or a second user account to run against.
type hiveTarget struct {
	// Interactive is false for "use HKEY_CURRENT_USER".
	Interactive bool
	// SID is the interactive user's SID in string form, set only when
	// Interactive is true.
	SID string
}

// hiveFacts is the machine-dependent half of the decision, injected as
// functions so chooseUserHive itself touches no syscall.
//
// Each returns an ERROR rather than a zero value on failure, deliberately.
// Every one of these three questions has a plausible-looking "just say no"
// answer — not elevated, no SID, empty string — and every one of those would
// send chooseUserHive to CURRENT_USER, which is the silent wrong-hive write
// this file exists to prevent. See processIsElevated for the concrete case
// where the x/sys convenience method does exactly that.
type hiveFacts struct {
	// elevated reports whether THIS process's token is elevated.
	elevated func() (bool, error)
	// processUser returns THIS process's token user SID, in string form.
	processUser func() (string, error)
	// interactiveUser returns the SID of the user logged on at the physical
	// console, in string form.
	interactiveUser func() (string, error)
}

// chooseUserHive decides which hive the per-user settings belong in.
//
// # Why "not elevated" is answered first, and answered with CURRENT_USER
//
// An unelevated dpb runs as whoever started it, and that person's HKCU is
// their own hive — the browser dpb is configuring is theirs. There is no
// discrepancy to detect, so there is nothing to look up, and looking anyway
// would make the COMMON case depend on machinery that can fail. That matters
// more here than it looks: proxy mode's supported installation
// (cliapp/service_task_windows.go) is a Scheduled Task with a logon trigger
// running AS THE INTERACTIVE USER, so this branch is the normal path.
//
// # Why the elevated case still usually ends up at CURRENT_USER
//
// On a machine with one account, UAC asks for CONSENT and the elevated process
// carries that same user's (elevated) token, so its SID matches the console
// user's and HKCU is already correct. Using CURRENT_USER there rather than
// HKEY_USERS\<SID> is not just an optimisation: it is the handle Windows
// itself maintains for that user, and it keeps the elevated single-account
// machine on exactly the code path it was on before this file existed.
//
// Only when the two SIDs genuinely DIFFER — the separate-administrator
// machine — does the hive move.
//
// # Why every failure is an error
//
// See this file's header. A failure here means "I could not find out whose
// settings these are", and the one thing that must not happen is for that to
// be reported as a definite answer.
func chooseUserHive(f hiveFacts) (hiveTarget, error) {
	elevated, err := f.elevated()
	if err != nil {
		return hiveTarget{}, fmt.Errorf("netstate: cannot tell whether this process is elevated, so it cannot tell whether HKCU is the logged-on user's hive or an administrator's: %w", err)
	}
	if !elevated {
		return hiveTarget{}, nil
	}

	mine, err := f.processUser()
	if err != nil {
		return hiveTarget{}, fmt.Errorf("netstate: this process is elevated, so HKCU may belong to an administrator rather than to the logged-on user, and this process's own account could not be identified: %w", err)
	}
	if mine == "" {
		return hiveTarget{}, errors.New("netstate: this process is elevated and its own account resolved to an empty SID, which cannot be compared with the logged-on user's")
	}

	theirs, err := f.interactiveUser()
	if err != nil {
		return hiveTarget{}, fmt.Errorf("netstate: this process is elevated, so HKCU may belong to an administrator rather than to the logged-on user, and the logged-on user could not be identified: %w", err)
	}
	if theirs == "" {
		return hiveTarget{}, errors.New("netstate: the logged-on user resolved to an empty SID, which names no hive")
	}

	// EqualFold, not ==: a SID string is canonical uppercase out of
	// ConvertSidToStringSid, so this should never matter, but comparing two
	// strings that came from different Win32 calls case-sensitively is the
	// kind of assumption that fails silently — and failing to notice that the
	// two are the SAME user would move a correct HKCU write to a hive path for
	// no reason.
	if strings.EqualFold(mine, theirs) {
		return hiveTarget{}, nil
	}
	return hiveTarget{Interactive: true, SID: theirs}, nil
}

// resolveUserHive turns chooseUserHive's decision into a usable root.
//
// # Why the HKEY_USERS\<SID> root is probed before it is used
//
// The writers below this reach the registry through registry.CreateKey, which
// CREATES what is missing — the right call for a machine whose Internet
// Settings key has somehow been deleted, and a disaster one level up: given
// `HKU\<SID>\Software\...`, CreateKey would happily materialise the <SID> root
// itself if that user's hive were not loaded, and every subsequent write would
// succeed into a phantom hive nothing reads. That is the same silent success
// this whole file is about, arrived at from the other direction. Opening the
// root first, for QUERY_VALUE only (the least access that proves existence),
// turns "that user is not logged on any more" into a refusal.
func resolveUserHive(f hiveFacts) (userHive, error) {
	t, err := chooseUserHive(f)
	if err != nil {
		return userHive{}, err
	}
	if !t.Interactive {
		return currentUserHive, nil
	}

	root, err := registry.OpenKey(registry.USERS, t.SID, registry.QUERY_VALUE)
	if err != nil {
		return userHive{}, fmt.Errorf("netstate: this process is elevated and belongs to a different account than the logged-on user (%s), whose registry hive HKU\\%s could not be opened: %w", t.SID, t.SID, err)
	}
	// Closed immediately: this was an EXISTENCE PROBE, not the handle the
	// callers use — see userHive for why they address the hive by path
	// instead. Unchecked for the same reason every other Close in this package
	// is: RegCloseKey on a handle RegOpenKeyEx just returned has nothing to
	// report, and refusing a correctly-identified hive over it would turn an
	// unrelated failure into the wrong-hive refusal this function exists to
	// reserve for a genuinely unknown user.
	defer root.Close()
	return userHive{root: registry.USERS, prefix: t.SID + `\`, name: `HKU\` + t.SID}, nil
}

// realHiveFacts is hiveFacts wired to the machine.
func realHiveFacts() hiveFacts {
	return hiveFacts{
		elevated:        processIsElevated,
		processUser:     processUserSID,
		interactiveUser: interactiveUserSID,
	}
}

// HiveStatus reports, for `dpb doctor`, which registry hive this process's
// per-user proxy and environment writes would land in right now.
//
// It is a read-only restatement of resolveUserHive's decision — not a second
// copy of the logic — so a caller outside this package (cliapp's
// doctor_windows.go) can surface Task 4's failure mode without duplicating
// chooseUserHive: on a standard-user-plus-separate-administrator machine, an
// elevated dpb's HKCU is the ADMINISTRATOR's hive, not the signed-in user's,
// and a proxy write that reports success there configures a browser nobody
// is looking at. interactive is true exactly when label names HKU\<SID>
// rather than HKCU, i.e. exactly the case this whole file exists for.
//
// Like every other read in this package, a failure is returned as an error
// naming what could not be determined, never guessed at as HKCU — see this
// file's header for why.
func HiveStatus() (label string, interactive bool, err error) {
	h, err := resolveUserHive(realHiveFacts())
	if err != nil {
		return "", false, err
	}
	return h.name, !h.isCurrentUser(), nil
}

// userHive returns the hive this port's per-user controllers read and write,
// resolving it on first use and PINNING it for the rest of the port's life.
//
// Pinning is a correctness choice, not a cache for speed. netstate captures the
// user's previous settings on the way in and puts them back on the way out, and
// those two operations have to address the same hive: if the console user
// changed in between, re-resolving would restore one person's captured settings
// into another person's hive. With the hive pinned, that machine state instead
// makes the HKU\<SID> path fail to open — a loud error on the revert, which is
// the honest outcome, rather than a quiet write to a stranger's account.
//
// "Fail to open" is a promise about the WRITERS as much as the readers, and it
// is kept by userHive.requireLoaded, which every writer in this package goes
// through: registry.CreateKey on its own would have re-created the unloaded
// hive's whole branch instead of failing. See requireLoaded.
//
// A FAILURE is not pinned. A failed resolution aborts whatever operation asked
// for it, so nothing has been done under a wrong assumption yet, and a
// transient failure (the console session mid-attach, say) must not disable the
// port permanently.
func (p *port) userHive() (userHive, error) {
	p.hiveMu.Lock()
	defer p.hiveMu.Unlock()
	if p.hiveOK {
		return p.hive, nil
	}
	h, err := resolveUserHive(realHiveFacts())
	if err != nil {
		return userHive{}, err
	}
	p.hive, p.hiveOK = h, true
	return h, nil
}

// processIsElevated reports whether this process's token is elevated.
//
// # Why this is not windows.Token.IsElevated
//
// x/sys/windows carries exactly this function already, and it is the wrong
// shape for this caller. Its whole body, from security_windows.go in
// golang.org/x/sys@v0.43.0:
//
//	func (token Token) IsElevated() bool {
//		var isElevated uint32
//		var outLen uint32
//		err := GetTokenInformation(token, TokenElevation, ...)
//		if err != nil {
//			return false
//		}
//		return outLen == uint32(unsafe.Sizeof(isElevated)) && isElevated != 0
//	}
//
// A failed query returns FALSE — indistinguishable from a genuinely
// unelevated process. chooseUserHive reads false as "CURRENT_USER is correct,
// no need to look further", so adopting it would convert "I could not find
// out" into the exact silent wrong-hive write this file was written to
// prevent. It is the same defect shape this project has now found six times in
// code that compiles and looks correct (syscall.Sendto, internal/poll's
// RawWrite, os.Process.Signal and three more), and the reason iphlp.go refuses
// to invent a return value for the void InitializeUnicastIpAddressEntry.
//
// TOKEN_QUERY is the documented access right for GetTokenInformation. See
// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
func processIsElevated() (bool, error) {
	tok, err := openProcessQueryToken()
	if err != nil {
		return false, err
	}
	defer tok.Close()

	var elevation uint32
	var got uint32
	want := uint32(unsafe.Sizeof(elevation))
	if err := windows.GetTokenInformation(tok, windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)), want, &got); err != nil {
		return false, fmt.Errorf("query TokenElevation on this process's token: %w", err)
	}
	// A short answer is not a "no". TOKEN_ELEVATION is a single DWORD, so
	// anything else means the call did not fill the field this reads, and
	// reading an uninitialised local as "not elevated" is the liar shape above.
	if got != want {
		return false, fmt.Errorf("query TokenElevation on this process's token: returned %d bytes, want %d", got, want)
	}
	return elevation != 0, nil
}

// processUserSID returns this process's token user SID in string form.
func processUserSID() (string, error) {
	tok, err := openProcessQueryToken()
	if err != nil {
		return "", err
	}
	defer tok.Close()
	return tokenUserSID(tok, "this process's token")
}

// openProcessQueryToken opens this process's token for querying.
//
// windows.OpenCurrentProcessToken does the same thing and is marked Deprecated
// in x/sys@v0.43.0 ("Explicitly call OpenProcessToken(CurrentProcess(), ...)
// with the desired access instead"), which is what this does.
func openProcessQueryToken() (windows.Token, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return 0, fmt.Errorf("open this process's access token: %w", err)
	}
	return tok, nil
}

// tokenUserSID reads a token's user SID and renders it as a string.
//
// The empty check is not defensive padding. windows.SID.String() swallows its
// error — "if e != nil { return \"\" }" in security_windows.go — so an empty
// string here means the CONVERSION FAILED, not that the token has no user. An
// empty SID travelling on would become the hive path `HKU\` + `\...`, which
// names no user at all; whose settings those are is precisely the question the
// caller has to be told cannot be answered.
func tokenUserSID(tok windows.Token, what string) (string, error) {
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read the user of %s: %w", what, err)
	}
	if u == nil || u.User.Sid == nil {
		return "", fmt.Errorf("read the user of %s: the token reported no user SID", what)
	}
	sid := u.User.Sid.String()
	if sid == "" {
		return "", fmt.Errorf("read the user of %s: the user SID could not be converted to a string", what)
	}
	return sid, nil
}

// interactiveUserSID returns the SID of the user logged on at the physical
// console.
//
// # Two routes, because one of them is unavailable exactly when it is needed
//
// The obvious route is WTSQueryUserToken on the console session, and MSDN is
// blunt about what it costs: "To call this function successfully, the calling
// application must be running within the context of the LocalSystem account
// and have the SE_TCB_NAME privilege."
// https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken
//
// An elevated administrator is not LocalSystem and does not hold SE_TCB_NAME —
// it is not in the Administrators group's default privilege set, and a
// privilege a token does not HOLD cannot be enabled. So on the
// separate-administrator machine, which is the entire reason this file exists,
// that route fails with ERROR_PRIVILEGE_NOT_HELD every time. A fix that only
// worked under LocalSystem would leave the common case exactly as broken as it
// was, only louder.
//
// The second route asks the session itself who owns it —
// WTSQuerySessionInformationW for WTSUserName and WTSDomainName, then
// LookupAccountName — and needs no privilege beyond the Query Information
// permission MSDN names for another user's session, which an administrator
// has and which is implicit for one's own session. Under over-the-shoulder UAC
// elevation the elevated process sits in the console session already.
//
// This is NOT a fallback in the sense this project bans. Both routes answer the
// SAME question — who is logged on at the console — and neither substitutes a
// guess for an answer. When both fail, so does this, naming both failures.
//
// The privileged route is tried FIRST because it is the more authoritative of
// the two: the SID comes straight off the kernel's token for that session, with
// no name-to-SID lookup that a detached domain member could resolve
// differently or not at all.
func interactiveUserSID() (string, error) {
	session := windows.WTSGetActiveConsoleSessionId()
	// MSDN: "If there is no session attached to the physical console, (for
	// example, if the physical console session is in the process of being
	// attached or detached), this function returns 0xFFFFFFFF."
	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-wtsgetactiveconsolesessionid
	if session == noConsoleSession {
		return "", errors.New("no session is attached to the physical console, so there is no logged-on user to configure")
	}

	sid, tokErr := consoleUserSIDFromToken(session)
	if tokErr == nil {
		return sid, nil
	}
	sid, nameErr := consoleUserSIDFromSessionOwner(session)
	if nameErr == nil {
		return sid, nil
	}
	return "", fmt.Errorf("console session %d: WTSQueryUserToken: %v; and asking the session who owns it: %w", session, tokErr, nameErr)
}

// noConsoleSession is WTSGetActiveConsoleSessionId's documented failure value.
// It is a constant rather than an inline literal because it is the one value
// that must never be passed on to WTSQueryUserToken as if it were a session.
const noConsoleSession = 0xFFFFFFFF

// consoleUserSIDFromToken is the LocalSystem route. See interactiveUserSID.
func consoleUserSIDFromToken(session uint32) (string, error) {
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return "", err
	}
	// MSDN, "Caution": "Service providers must close token handles after they
	// have finished using them." This is a real primary token, not one of
	// x/sys's pseudo-handles, so leaking it leaks a user token per call and
	// Live is called on every proxy Verify.
	defer tok.Close()
	return tokenUserSID(tok, fmt.Sprintf("the console session %d user token", session))
}

// consoleUserSIDFromSessionOwner is the privilege-free route. See
// interactiveUserSID.
//
// The domain is prepended when the session reports one so that two accounts
// with the same name in different domains cannot be confused; MSDN calls
// WTSDomainName "the name of the domain to which the logged-on user belongs",
// and on a workgroup machine it is the machine name, which resolves locally.
func consoleUserSIDFromSessionOwner(session uint32) (string, error) {
	user, err := wtsSessionString(session, wtsUserName)
	if err != nil {
		return "", fmt.Errorf("read WTSUserName: %w", err)
	}
	if user == "" {
		// An empty user name is the session saying nobody is signed in — a
		// real answer, and one that must not be turned into a lookup of the
		// empty account name.
		return "", fmt.Errorf("session %d reports no user name, so nobody is logged on there", session)
	}
	domain, err := wtsSessionString(session, wtsDomainName)
	if err != nil {
		return "", fmt.Errorf("read WTSDomainName: %w", err)
	}

	account := user
	if domain != "" {
		account = domain + `\` + user
	}
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return "", fmt.Errorf("look up the SID of %q: %w", account, err)
	}
	if sid == nil {
		return "", fmt.Errorf("look up the SID of %q: no SID was returned", account)
	}
	s := sid.String()
	if s == "" {
		return "", fmt.Errorf("look up the SID of %q: the SID could not be converted to a string", account)
	}
	return s, nil
}

// The two WTS_INFO_CLASS members this file asks for. wtsapi32.h declares the
// enumeration with no explicit values, so these are ORDINALS counted from
// WTSInitialProgram = 0 in the order MSDN prints:
//
//	WTSInitialProgram, WTSApplicationName, WTSWorkingDirectory, WTSOEMId,
//	WTSSessionId, WTSUserName, WTSWinStationName, WTSDomainName, ...
//
// https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_info_class
//
// Both of these classes return "a null-terminated string", which is what makes
// wtsSessionString's LPWSTR handling correct for them and for nothing else in
// that enumeration: WTSSessionId, for instance, returns a ULONG, and reading it
// as a string would walk off the end of a four-byte buffer. userhive_test.go
// pins both numbers, because getting one wrong reads a DIFFERENT class of
// session information rather than failing.
const (
	wtsUserName   = 5
	wtsDomainName = 7
)

// wtsCurrentServerHandle is WTS_CURRENT_SERVER_HANDLE, which wtsapi32.h defines
// as ((HANDLE)NULL) — MSDN: "specify WTS_CURRENT_SERVER_HANDLE to indicate the
// RD Session Host server on which your application is running".
const wtsCurrentServerHandle = windows.Handle(0)

// wtsSessionString asks the session manager one string-valued question about a
// session.
//
// The buffer comes back from wtsapi32's own allocator, and MSDN's ppBuffer
// description is explicit about the obligation: "To free the returned buffer,
// call the WTSFreeMemory function."
func wtsSessionString(session uint32, class uint32) (string, error) {
	var buf *uint16
	var n uint32
	if err := WTSQuerySessionInformationW(wtsCurrentServerHandle, session, class, &buf, &n); err != nil {
		return "", err
	}
	if buf == nil {
		// A successful call that handed back no buffer is not an empty string,
		// it is an answer this function cannot read. Saying "" would make
		// consoleUserSIDFromSessionOwner report "nobody is logged on".
		return "", errors.New("WTSQuerySessionInformationW succeeded but returned no buffer")
	}
	// buf points into wtsapi32's heap, not into Go memory, so converting it to
	// a uintptr here rather than inside a Call argument list is safe: there is
	// nothing for the garbage collector to keep alive or move. That is the one
	// case iphlp.go's //go:uintptrescapes warning on SendMessageTimeoutW does
	// not apply to, and it is said out loud so the difference is not read as an
	// oversight.
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf), nil
}

// procWTSQuerySessionInformationW lives here rather than in iphlp.go for the
// reason proxy.go's procGlobalFree does: iphlp.go's package comment names "the
// thirteen Win32 procedures" it wraps and iphlp_test.go pins exactly those
// thirteen by name, and a test body may not be edited to add a fourteenth.
// Keeping the procedure beside its only caller means userhive_test.go carries
// its own resolve check rather than leaving it the one unpinned procedure in
// the package.
//
// wtsapi32.dll is a system DLL, so NewLazySystemDLL for the reason
// dll_windows.go gives NewLazyDLL: "using NewLazyDLL without an absolute path
// name is subject to DLL preloading attacks."
//
// x/sys@v0.43.0 already carries WTSQueryUserToken, WTSEnumerateSessions,
// WTSFreeMemory and WTSGetActiveConsoleSessionId (security_windows.go), which
// is why only this one is wrapped by hand.
var (
	modwtsapi32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = modwtsapi32.NewProc("WTSQuerySessionInformationW")
)

// WTSQuerySessionInformationW retrieves session information for the specified
// session on the specified RD Session Host server. See
// https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw
//
//	BOOL WTSQuerySessionInformationW(
//	  [in]  HANDLE         hServer,
//	  [in]  DWORD          SessionId,
//	  [in]  WTS_INFO_CLASS WTSInfoClass,
//	  [out] LPWSTR         *ppBuffer,
//	  [out] DWORD          *pBytesReturned
//	);
//
// wtsapi32 convention: BOOL return, and MSDN says "If the function succeeds,
// the return value is a nonzero value. If the function fails, the return value
// is zero. To get extended error information, call GetLastError." — which
// LazyProc.Call already hands back as its third value. That is the SAME
// convention iphlp.go's wininet/winhttp/user32 wrappers use and the INVERSE of
// the iphlpapi one, where the return value is itself the error code; see that
// file's package comment for why the difference is spelled out every time.
//
// ppBuffer is taken as the typed **uint16 it is, not as a uintptr the caller
// already converted, so that the unsafe.Pointer→uintptr conversion happens
// inside Call's own argument list where //go:uintptrescapes can keep the
// variable alive across the syscall — the same signature rule SendMessageTimeoutW
// carries in iphlp.go, and for the same reason.
func WTSQuerySessionInformationW(server windows.Handle, sessionID uint32, infoClass uint32, ppBuffer **uint16, bytesReturned *uint32) error {
	r0, _, err := procWTSQuerySessionInformationW.Call(
		uintptr(server),
		uintptr(sessionID),
		uintptr(infoClass),
		uintptr(unsafe.Pointer(ppBuffer)),
		uintptr(unsafe.Pointer(bytesReturned)),
	)
	if r0 == 0 {
		return err
	}
	return nil
}
