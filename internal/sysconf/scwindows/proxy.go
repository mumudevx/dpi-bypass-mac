//go:build windows

package scwindows

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/mumudevx/dpb/internal/sysport"
)

// proxyCtl is the Windows ProxyController.
//
// # Contract 1, restated for this file
//
// The setters write REGISTRY VALUES under HKCU\...\Internet Settings through
// advapi32's RegSetValueExW. Live reads through winhttp.dll's
// WinHttpGetIEProxyConfigForCurrentUser, which does not hand back the bytes we
// wrote: it returns the RESOLVED per-user configuration WinHTTP itself would
// use, with lpszProxy already gated on ProxyEnable. That is a different DLL
// answering a different question, which is what makes it the independent
// verifier here — the Windows analogue of scdarwin's networksetup-writes /
// scutil-reads split, and a genuinely stronger separation than the one
// windows.go's Contract 2 has to admit for routes.
//
// Configured is the CAPTURE read and deliberately goes back through the
// registry, for the reason scdarwin.proxyCtl.Configured gives: a capture must
// record what the writer will later have to put back, value for value.
type proxyCtl struct{ p *port }

var _ sysport.ProxyController = proxyCtl{}

// The registry location every Windows proxy setting lives in, and the three
// values this file reads and writes. See
// https://learn.microsoft.com/en-us/troubleshoot/developer/browsers/connectivity-navigation/use-proxy-servers-with-ie
// (the "Internet Settings" registry values) and WinHTTP's own description of
// the same values under WINHTTP_CURRENT_USER_IE_PROXY_CONFIG.
//
// # KNOWN LIMITATION: HKCU here is the ELEVATED token's hive
//
// Every read and write below opens registry.CURRENT_USER, and CURRENT_USER is
// resolved from the ACCESS TOKEN OF THE CALLING PROCESS — MSDN, "Predefined
// Keys": HKEY_CURRENT_USER "maps to the current user's branch in
// HKEY_USERS ... the user's [hive] is loaded when the user logs on". dpb needs
// elevation on Windows to write routes, so on the enterprise-default machine —
// a standard user account plus a SEPARATE administrator account, where the UAC
// prompt asks for the admin's credentials rather than consent — the elevated
// process runs as the ADMIN and HKCU is the ADMIN's hive.
//
// The consequence is exactly the failure class this package's verification
// contract exists to catch, and it is not caught, because it is not a failed
// write: SetManual writes the admin's Internet Settings, Live reads the same
// token's configuration back through WinHTTP, Verify passes, and the
// interactive user's browser is never proxied at all. dpb reports Ready while
// changing nothing the user can see. The revert is symmetric and equally
// invisible, so nothing is left broken — but nothing was ever done either.
//
// Fixing it properly means obtaining the INTERACTIVE user's token
// (WTSQueryUserToken on the active session, or WTSGetActiveConsoleSessionId +
// ImpersonateLoggedOnUser) and loading that user's hive, which is a
// substantial piece of work with its own privilege and lifetime questions. It
// is deliberately NOT attempted here; it is the top item for the first session
// on a real Windows machine, where "did the browser actually get proxied" can
// be observed rather than reasoned about. env.go carries the same limitation
// for HKCU\Environment.
const (
	internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

	valAutoConfigURL = "AutoConfigURL" // REG_SZ,   the PAC URL; its ABSENCE is "off"
	valProxyEnable   = "ProxyEnable"   // REG_DWORD, the single global manual-proxy switch
	valProxyServer   = "ProxyServer"   // REG_SZ,   every scheme's proxy, in ONE string
)

// The two handle-less wininet options that push a registry change out to
// already-running processes. From wininet.h:
//
//	#define INTERNET_OPTION_REFRESH          37
//	#define INTERNET_OPTION_PROXY            38
//	#define INTERNET_OPTION_SETTINGS_CHANGED 39
//
// Both are called with hInternet = NULL, which is the documented idiom for the
// process-global options. See InternetSetOptionW's wrapper in iphlp.go.
const (
	internetOptionRefresh         = 37
	internetOptionSettingsChanged = 39
)

// procGlobalFree lives here rather than in iphlp.go on purpose. iphlp.go's
// package comment names "the twelve Win32 procedures" it wraps and
// iphlp_test.go pins exactly those twelve by name; GlobalFree is not one of
// them, it exists solely to discharge the obligation
// WinHttpGetIEProxyConfigForCurrentUser hands its caller, and that caller is
// this file. Keeping it beside the struct whose fields it frees means the
// allocation and the release are readable together, and proxy_test.go carries
// its own resolve check rather than leaving the thirteenth procedure the only
// unpinned one.
var (
	modkernel32    = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalFree = modkernel32.NewProc("GlobalFree")
)

// GlobalFree releases a block allocated with the global heap functions. See
// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globalfree
//
// kernel32 convention, and it is the INVERSE of the BOOL convention iphlp.go's
// wininet and winhttp wrappers use — which is exactly why it is spelled out
// rather than copied: MSDN says "If the function succeeds, the return value is
// NULL. If the function fails, the return value is equal to a handle to the
// global memory object. To get extended error information, call
// GetLastError." So a NON-ZERO return is the failure here, where a zero return
// is the failure there. Testing r0 the wrong way round would report every
// successful free as an error and every leak as a success.
func GlobalFree(mem unsafe.Pointer) error {
	r0, _, err := procGlobalFree.Call(uintptr(mem))
	if r0 != 0 {
		return err
	}
	return nil
}

// winhttpCurrentUserIEProxyConfig is WINHTTP_CURRENT_USER_IE_PROXY_CONFIG.
// golang.org/x/sys/windows does not declare it, so — unlike every iphlpapi
// struct this package uses — it has to be declared here. MSDN:
//
//	typedef struct {
//	  BOOL   fAutoDetect;
//	  LPWSTR lpszAutoConfigUrl;
//	  LPWSTR lpszProxy;
//	  LPWSTR lpszProxyBypass;
//	} WINHTTP_CURRENT_USER_IE_PROXY_CONFIG;
//
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_current_user_ie_proxy_config
//
// # Why int32 and not bool
//
// windef.h has `typedef int BOOL;` — a 32-bit signed integer, not a byte. A Go
// `bool` field would be one byte, and on amd64 the following pointer would
// still land at offset 8 because of alignment, so the struct SIZE would look
// right while the field READ only the low byte of the BOOL. TRUE is 1 so it
// would usually work, which is the worst possible failure: any API that
// answers with a different non-zero value, or a 32-bit target where the
// following offsets also shift, reads fAutoDetect as false and nobody finds
// out.
//
// # Why there is no explicit padding field
//
// gc lays struct fields out in declaration order at each field's natural
// alignment — the same guarantee every struct in x/sys/windows/types_windows.go
// already depends on — and that is precisely what MSVC does under its default
// packing. So on amd64 and arm64 (pointer align 8) the compiler inserts four
// bytes after fAutoDetect and the offsets are 0, 8, 16, 24 with size 32; on a
// 32-bit Windows target (386, arm; pointer align 4) it inserts nothing and the
// offsets are 0, 4, 8, 12 with size 16. Both match the C struct. Writing an
// explicit `_ [4]byte` here would hard-code the 64-bit answer and silently
// corrupt the 32-bit one — the field-offset failure iphlp.go's package comment
// refuses to risk for MibIpForwardRow2, arrived at from the other direction.
//
// # The three strings are ours to free
//
// MSDN, "Remarks": "The caller must free the lpszProxy, lpszProxyBypass, and
// lpszAutoConfigUrl strings if they are non-NULL. Use the GlobalFree function
// to free the strings." The struct itself is caller-allocated (it is a local
// here) and is not freed. Live is called on every proxy Verify, so a missed
// free is a leak per verification, not a one-off.
type winhttpCurrentUserIEProxyConfig struct {
	fAutoDetect       int32
	lpszAutoConfigURL *uint16
	lpszProxy         *uint16
	lpszProxyBypass   *uint16
}

// free releases the three caller-owned strings and nils them, so it is safe to
// call on a struct that was never filled in and safe to call twice.
//
// A GlobalFree that fails is LOGGED, not returned: the read it belongs to has
// already produced a correct answer, there is nothing the caller could do
// differently, and turning a leaked string into a failed Verify would report a
// working proxy as broken. It is still said out loud, because a leak nobody
// mentions is a leak nobody fixes.
func (cfg *winhttpCurrentUserIEProxyConfig) free(logf func(string, ...any)) {
	for _, pp := range []**uint16{&cfg.lpszAutoConfigURL, &cfg.lpszProxy, &cfg.lpszProxyBypass} {
		if *pp == nil {
			continue
		}
		if err := GlobalFree(unsafe.Pointer(*pp)); err != nil {
			logf("netstate: GlobalFree on a WinHTTP proxy string failed: %v (the string is leaked)", err)
		}
		*pp = nil
	}
}

// proxyService is the single pseudo-service Windows has. Windows keeps ONE
// proxy configuration per user, under HKCU, and no per-network-service state
// at all — which is why windows.go withholds sysport.CapPerService permanently
// rather than pending.
//
// The name is chosen to read correctly where callers put it, because they all
// put it in a sentence: netstate's proxyOp.Describe says "set auto-proxy URL
// %s on %s" and op_proxy.go's revert check says "still reports our auto-proxy
// URL %s on %s". "…on the current user's Internet Settings" is true (it names
// the registry hive that is actually written) and reads as English in both.
const proxyService = "the current user's Internet Settings"

// Services returns the one pseudo-service. It cannot fail: there is nothing to
// enumerate.
func (c proxyCtl) Services(_ context.Context) ([]string, error) {
	return []string{proxyService}, nil
}

// The svc argument is accepted and ignored by every writer below, and that is
// deliberate rather than sloppy. There is one setting; writing it twice
// because a caller named two services is idempotent and harmless, whereas
// REFUSING an unrecognised name would make a journal written by a version that
// spelled proxyService differently unrevertible — and netstate.Record's
// contract is that a journal entry stays self-sufficient across versions.

// Configured reads the stored configuration back out of the registry — the
// same subsystem the setters write to. It is for CAPTURE, never verification;
// Live is the verifier.
//
// kinds narrows what is read. Windows keeps every manual scheme in ONE value
// (ProxyServer), so narrowing cannot reduce a web-or-SOCKS capture below a
// single read; what it does guarantee is the thing Plan 1 asked for — a
// SOCKS-only capture never touches AutoConfigURL, and a PAC capture never
// touches ProxyEnable/ProxyServer, so a value that is missing, of the wrong
// type, or unreadable for a setting this caller will not restore cannot abort
// the apply.
//
// A value that does not exist is not an error. registry.ErrNotExist is a
// POSITIVE statement from the registry — "no such value has ever been
// written" — which is exactly the "there was nothing here" a capture needs to
// record, and is not the ambiguous empty answer windows.go's Contract 1 warns
// about.
func (c proxyCtl) Configured(_ context.Context, _ string, kinds ...sysport.ProxyKind) (sysport.ProxySettings, error) {
	if len(kinds) == 0 {
		kinds = allProxyKinds
	}
	p := sysport.ProxySettings{Kinds: append([]sysport.ProxyKind(nil), kinds...)}

	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return p, fmt.Errorf("netstate: open HKCU\\%s: %w", internetSettingsKey, err)
	}
	defer key.Close()

	if proxyWants(p, sysport.ProxyAuto) {
		url, err := regString(key, valAutoConfigURL)
		if err != nil {
			return p, err
		}
		p.AutoURL = url
		// Windows has no separate PAC enable bit: the value's presence IS the
		// switch. See Restore for the consequence on the way back out.
		p.AutoOn = url != ""
	}

	if proxyWants(p, sysport.ProxyWeb) || proxyWants(p, sysport.ProxySOCKS) {
		on, list, err := readProxyServer(key)
		if err != nil {
			return p, err
		}
		if proxyWants(p, sysport.ProxyWeb) {
			if e, ok := findProxyEntry(list, schemeHTTP); ok {
				p.WebHost, p.WebPort, p.WebOn = e.Host, e.Port, on && e.Host != ""
			}
			if e, ok := findProxyEntry(list, schemeHTTPS); ok {
				p.SecureHost, p.SecurePort, p.SecureOn = e.Host, e.Port, on && e.Host != ""
			}
		}
		if proxyWants(p, sysport.ProxySOCKS) {
			if e, ok := findProxyEntry(list, schemeSOCKS); ok {
				p.SOCKSHost, p.SOCKSPort, p.SOCKSOn = e.Host, e.Port, on && e.Host != ""
			}
		}
	}

	return p, nil
}

// SetAuto points the user at a PAC URL by writing AutoConfigURL. There is no
// second "state" write to pair with it, unlike macOS: on Windows the value's
// presence is the enable.
func (c proxyCtl) SetAuto(_ context.Context, _ string, url string) error {
	key, err := openInternetSettings()
	if err != nil {
		return err
	}
	defer key.Close()

	if err := key.SetStringValue(valAutoConfigURL, url); err != nil {
		return fmt.Errorf("netstate: set %s: %w", valAutoConfigURL, err)
	}
	return notifyProxyChanged()
}

// SetManual installs an explicit host:port proxy.
//
// It READS ProxyServer, replaces only this kind's schemes, and re-emits the
// whole string. Overwriting the value outright would be a data-loss bug rather
// than a style choice: Windows packs every scheme into one string, so
// `ProxyServer = "https=ours:8080"` deletes the user's own http and ftp
// proxies as a side effect of setting HTTPS.
//
// ProxyWeb sets BOTH http and https, matching scdarwin (which issues
// -setwebproxy and -setsecurewebproxy together) and matching what
// netstate/op_proxy.go's Verify then demands: OpProxyHTTP checks the HTTP pair
// AND the HTTPS pair.
func (c proxyCtl) SetManual(_ context.Context, svc string, kind sysport.ProxyKind, host string, port int) error {
	var schemes []string
	switch kind {
	case sysport.ProxyWeb:
		schemes = []string{schemeHTTP, schemeHTTPS}
	case sysport.ProxySOCKS:
		schemes = []string{schemeSOCKS}
	default:
		// Refused by name with a reason, never skipped quietly — the same
		// refusal scdarwin makes: a PAC URL is not a host:port and SetAuto is
		// the verb that installs one.
		return fmt.Errorf("netstate: SetManual cannot install an auto-proxy (PAC) setting on %s; use SetAuto", svc)
	}

	key, err := openInternetSettings()
	if err != nil {
		return err
	}
	defer key.Close()

	_, list, err := readProxyServer(key)
	if err != nil {
		return err
	}
	for _, s := range schemes {
		list = setProxyEntry(list, proxyEntry{Scheme: s, Host: host, Port: port})
	}

	// ProxyServer first, ProxyEnable second, so there is no instant in which
	// the global switch is on while the string still names the old proxy.
	if err := key.SetStringValue(valProxyServer, formatProxyServer(list)); err != nil {
		return fmt.Errorf("netstate: set %s: %w", valProxyServer, err)
	}
	if err := key.SetDWordValue(valProxyEnable, 1); err != nil {
		return fmt.Errorf("netstate: set %s: %w", valProxyEnable, err)
	}
	return notifyProxyChanged()
}

// Restore puts the captured configuration back. It is idempotent: every write
// sets an absolute value rather than toggling one.
func (c proxyCtl) Restore(_ context.Context, _ string, prev sysport.ProxySettings) error {
	// A capture that names no kinds is refused, never read as "all".
	// proxyWants answers "all" for an empty Kinds — right for Configured, a
	// read — so without this a zero-value ProxySettings would delete
	// AutoConfigURL and strip every scheme out of ProxyServer. See
	// sysport.ProxySettings.CheckRestorable for the asymmetry.
	if err := prev.CheckRestorable(); err != nil {
		return err
	}

	key, err := openInternetSettings()
	if err != nil {
		return err
	}
	defer key.Close()

	var firstErr error
	fail := func(e error) {
		if firstErr == nil {
			firstErr = e
		}
	}

	if proxyWants(prev, sysport.ProxyAuto) {
		if err := restoreAutoConfigURL(key, prev); err != nil {
			fail(err)
		}
	}
	if proxyWants(prev, sysport.ProxyWeb) || proxyWants(prev, sysport.ProxySOCKS) {
		if err := c.restoreProxyServer(key, prev); err != nil {
			fail(err)
		}
	}

	// Notify even when a write failed: the writes that DID land still have to
	// reach running processes, and a half-restored configuration that nobody
	// picks up is strictly worse than a half-restored one that they do.
	if err := notifyProxyChanged(); err != nil {
		fail(err)
	}
	return firstErr
}

// restoreAutoConfigURL puts the PAC setting back.
//
// A captured URL that was OFF is deleted rather than written back, and that is
// a deliberate asymmetry with macOS. macOS stores the URL and its enable bit
// separately, so scdarwin can restore "this URL, switched off". Windows has
// only the value's presence, so writing a disabled URL back would ENABLE it —
// pointing the user at a PAC they had switched off, which is a live behaviour
// change. Dropping an inert URL is the smaller loss.
func restoreAutoConfigURL(key registry.Key, prev sysport.ProxySettings) error {
	if prev.AutoURL != "" && prev.AutoOn {
		if err := key.SetStringValue(valAutoConfigURL, prev.AutoURL); err != nil {
			return fmt.Errorf("netstate: restore %s: %w", valAutoConfigURL, err)
		}
		return nil
	}
	// Deleting is the off switch here, so unlike scdarwin's "-setautoproxyurl
	// <svc> ''" it is NOT soft — it is the thing the user actually needs. A
	// value that is already gone is success, not a failure to tidy.
	if err := key.DeleteValue(valAutoConfigURL); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("netstate: clear %s: %w", valAutoConfigURL, err)
	}
	return nil
}

// restoreProxyServer rebuilds ProxyServer, touching only the schemes prev
// actually describes, and then decides what to do with the single global
// ProxyEnable switch. See decideProxyEnable for that decision.
func (c proxyCtl) restoreProxyServer(key registry.Key, prev sysport.ProxySettings) error {
	_, list, err := readProxyServer(key)
	if err != nil {
		return err
	}

	var described []string
	if proxyWants(prev, sysport.ProxyWeb) {
		described = append(described, schemeHTTP, schemeHTTPS)
		list = restoreScheme(list, schemeHTTP, prev.WebHost, prev.WebPort)
		list = restoreScheme(list, schemeHTTPS, prev.SecureHost, prev.SecurePort)
	}
	if proxyWants(prev, sysport.ProxySOCKS) {
		described = append(described, schemeSOCKS)
		list = restoreScheme(list, schemeSOCKS, prev.SOCKSHost, prev.SOCKSPort)
	}

	if s := formatProxyServer(list); s != "" {
		if err := key.SetStringValue(valProxyServer, s); err != nil {
			return fmt.Errorf("netstate: restore %s: %w", valProxyServer, err)
		}
	} else if err := key.DeleteValue(valProxyServer); err != nil && !errors.Is(err, registry.ErrNotExist) {
		// soft, for scdarwin's reason: clearing the stored string is tidying,
		// and what the user actually needs is the switch below. Said out loud
		// anyway, because a stale ProxyServer left behind a disabled switch is
		// how our dead port survives a clean exit.
		c.p.env().logf("netstate: clear %s: %v (tidying only; %s decides)", valProxyServer, err, valProxyEnable)
	}

	switch decideProxyEnable(prev, list, described) {
	case proxyEnableOn:
		if err := key.SetDWordValue(valProxyEnable, 1); err != nil {
			return fmt.Errorf("netstate: restore %s: %w", valProxyEnable, err)
		}
	case proxyEnableOff:
		if err := key.SetDWordValue(valProxyEnable, 0); err != nil {
			return fmt.Errorf("netstate: clear %s: %w", valProxyEnable, err)
		}
	case proxyEnableLeaveAlone:
	}
	return nil
}

// proxyEnableDecision is what a restore does with the single global switch.
// It is a named type rather than a *bool because "leave it alone" is a real,
// frequently-correct answer here and a nil pointer says that far less clearly.
type proxyEnableDecision int

const (
	proxyEnableLeaveAlone proxyEnableDecision = iota
	proxyEnableOff
	proxyEnableOn
)

// decideProxyEnable is the ProxyEnable half of a restore, split out of
// restoreProxyServer so the decision can be pinned by a test without a
// registry to open.
//
// This is the one place where Windows' shape and sysport's disagree, so it is
// spelled out rather than guessed. ProxySettings carries a PER-SCHEME "on"
// flag because macOS has per-scheme switches; Windows has exactly one, shared,
// and ProxySettings has no field for it.
//
// # The switch IS recoverable from the capture, and must be restored exactly
//
// Configured records each scheme's On as `ProxyEnable && host != ""`. So for
// any described scheme that captured a HOST, that scheme's On flag IS the
// ProxyEnable DWORD, bit for bit — capturedProxyEnable below recovers it. When
// the capture determines the switch that way, the switch is written back to
// exactly that value and nothing else is consulted.
//
// Getting this wrong is not cosmetic. An ex-corporate laptop with
// ProxyEnable = 0 and a stale bare ProxyServer ("proxy.corp:8080") is common,
// and a revert that leaves the switch at the 1 SetManual set routes every
// browser on the machine through a proxy the user had switched OFF, across
// reboots, while VerifyReverted passes because the HOST no longer matches
// ours. That is a stranger's laptop with no internet after a teardown this
// tool called clean.
//
// # When the capture does NOT determine it
//
// A capture whose described schemes all had EMPTY hosts (a SOCKS-only capture
// on a machine with no SOCKS proxy, say) says nothing about the switch: On is
// false whether ProxyEnable was 0 or 1. Two cases remain, and they are the
// original three-way decision minus the case above:
//
//   - nothing survives in ProxyServer from a scheme this capture never
//     described -> ProxyEnable = 0. Everything the switch could still be
//     gating is something we just restored as off or removed.
//   - an undescribed proxy (the user's SOCKS proxy during a web revert, a bare
//     token during a SOCKS revert) is still in the string -> LEAVE THE SWITCH
//     ALONE. Turning it off would disable a proxy this tool never touched,
//     which is the exact failure ProxySettings.Kinds exists to prevent, and
//     turning it on would enable one. Neither is knowable from here.
func decideProxyEnable(prev sysport.ProxySettings, list []proxyEntry, described []string) proxyEnableDecision {
	on, known := capturedProxyEnable(prev)
	switch {
	case on:
		return proxyEnableOn
	case known:
		return proxyEnableOff
	case !hasUndescribedProxy(list, described):
		return proxyEnableOff
	default:
		return proxyEnableLeaveAlone
	}
}

// capturedProxyEnable recovers the ProxyEnable DWORD the capture was taken
// under, and says whether it could.
//
// known is true when some scheme prev describes captured a non-empty host,
// because Configured's `on && e.Host != ""` makes that scheme's On flag equal
// to ProxyEnable exactly. `known || on` at the end covers the shape Configured
// cannot produce but a hand-built or older-version ProxySettings could — On
// set with no host — where the "on" answer is itself the knowledge.
func capturedProxyEnable(prev sysport.ProxySettings) (on, known bool) {
	if proxyWants(prev, sysport.ProxyWeb) {
		on = on || prev.WebOn || prev.SecureOn
		known = known || prev.WebHost != "" || prev.SecureHost != ""
	}
	if proxyWants(prev, sysport.ProxySOCKS) {
		on = on || prev.SOCKSOn
		known = known || prev.SOCKSHost != ""
	}
	return on, known || on
}

// restoreScheme writes one scheme back, or removes it when the capture holds
// no host for it. An empty host means either "there was nothing here" or "what
// was here was ours and notSelf stripped it" — both of which mean the entry
// must go, exactly as scdarwin's empty-host branch means "off".
func restoreScheme(list []proxyEntry, scheme, host string, port int) []proxyEntry {
	if host == "" {
		return removeProxyEntry(list, scheme)
	}
	return setProxyEntry(list, proxyEntry{Scheme: scheme, Host: host, Port: port})
}

// hasUndescribedProxy reports whether list still carries a proxy the capture
// never described — the thing that must hold the global switch on.
//
// A SYNTHESIZED entry (proxyEntry.Bare; see parseProxyServer) needs its own
// answer, and getting it wrong is how the ex-corporate-laptop failure in
// decideProxyEnable used to happen. A bare ProxyServer token is ONE proxy that
// this package expands into an http, an https and an ftp entry. The ftp entry
// is not a second proxy the user configured separately: it is the same value
// the capture already recorded as WebHost, seen through a scheme nobody asked
// about. So a bare-derived entry counts as undescribed only when the capture
// described NONE of the schemes the bare token covers — which is exactly the
// SOCKS-only capture, where the user's bare http proxy really is untouched
// configuration this restore knows nothing about and must not switch off.
func hasUndescribedProxy(list []proxyEntry, described []string) bool {
	bareDescribed := false
	for _, s := range bareProxySchemes {
		if containsScheme(described, s) {
			bareDescribed = true
			break
		}
	}
	for _, e := range list {
		if e.Bare {
			if bareDescribed {
				continue
			}
			return true
		}
		if !containsScheme(described, e.Scheme) {
			return true
		}
	}
	return false
}

func containsScheme(schemes []string, scheme string) bool {
	for _, s := range schemes {
		if s == scheme {
			return true
		}
	}
	return false
}

// Live reads the RESOLVED per-user proxy configuration out of WinHTTP and
// translates it into the scutil key names.
//
// # Why scutil's names on Windows
//
// sysport.ProxyState.Keys is a SHARED VOCABULARY, not a macOS leak, and this
// translation belongs here with the rest of the platform's dialect. The
// platform-free code that consumes it — netstate/op_proxy.go's Verify,
// VerifyReverted and checkProxyPair, cliapp/doctor.go, cliapp/coverage.go —
// asks for "HTTPSEnable" and "ProxyAutoConfigURLString" by name and must stay
// platform-free; the names happen to have come from scutil first because macOS
// shipped first. Renaming them to something platform-neutral would be a change
// to code this task must not touch, and would buy nothing: SOME name has to be
// agreed, and a name already agreed is worth more than a prettier one.
//
// The stakes are why this function is table-tested rather than eyeballed. A
// misspelled key does not fail to compile and does not fail loudly: Str
// returns "" and On returns false for an absent key, so a wrong name makes
// Verify report "auto-proxy disabled" for a working proxy, or — with an
// equally wrong name in VerifyReverted — makes a revert that left our proxy in
// place report success. Neither is detectable without a Windows machine.
func (c proxyCtl) Live(_ context.Context) (sysport.ProxyState, error) {
	var cfg winhttpCurrentUserIEProxyConfig
	// Deferred BEFORE the call, not after it. cfg starts zeroed and free skips
	// nil pointers, so this covers the success path, the error path, and the
	// case MSDN does not promise anything about — a call that filled one or
	// two of the strings and then failed. Deferring after a successful call
	// would leak in exactly that case.
	defer cfg.free(c.p.env().logf)

	if err := WinHttpGetIEProxyConfigForCurrentUser(unsafe.Pointer(&cfg)); err != nil {
		// Not softened into "no proxy configured", including for the
		// ERROR_FILE_NOT_FOUND this returns when there is no IE configuration
		// for the token (a service account, say). An empty answer is
		// indistinguishable from "no setting" to every caller above this
		// package — windows.go's Contract 1 — and a Verify that reads a failed
		// read as "nothing is set" reports a proxy we did set as missing.
		return sysport.ProxyState{}, fmt.Errorf("netstate: read proxy state: %w", err)
	}

	return proxyStateFromIE(
		cfg.fAutoDetect != 0,
		windows.UTF16PtrToString(cfg.lpszAutoConfigURL),
		windows.UTF16PtrToString(cfg.lpszProxy),
		windows.UTF16PtrToString(cfg.lpszProxyBypass),
	), nil
}

// The scutil key names. They are constants so that a typo is a compile error
// in one place instead of a silent mismatch in several; see Live for what a
// silent mismatch costs.
const (
	keyAutoDiscoveryEnable = "ProxyAutoDiscoveryEnable"
	keyAutoConfigEnable    = "ProxyAutoConfigEnable"
	keyAutoConfigURL       = "ProxyAutoConfigURLString"
)

// schemeToScutil maps the Windows scheme token to the scutil key prefix the
// three Enable/Proxy/Port triples are built from. ftp has no scutil analogue
// and no consumer, so it is preserved through parse/emit but never published.
var schemeToScutil = []struct{ scheme, prefix string }{
	{schemeHTTP, "HTTP"},
	{schemeHTTPS, "HTTPS"},
	{schemeSOCKS, "SOCKS"},
}

// proxyStateFromIE is the translation, split out from Live so it can be tested
// without a Windows machine: everything above it is one syscall, everything
// below it is arithmetic on strings.
func proxyStateFromIE(autoDetect bool, autoConfigURL, proxy, bypass string) sysport.ProxyState {
	st := sysport.ProxyState{Keys: map[string]string{}}

	// fAutoDetect is WPAD — "Automatically detect settings" in the Windows UI.
	// scutil's name for the same thing is ProxyAutoDiscoveryEnable. Nothing in
	// netstate reads it today; it is published because doctor prints what is
	// set, and a machine whose proxy comes from WPAD would otherwise show as
	// having no proxy at all.
	st.Keys[keyAutoDiscoveryEnable] = boolKey(autoDetect)

	// lpszAutoConfigUrl is the PAC URL, and its presence is the enable — there
	// is no separate bit on Windows. op_proxy.go's PAC Verify reads both keys.
	st.Keys[keyAutoConfigEnable] = boolKey(autoConfigURL != "")
	if autoConfigURL != "" {
		st.Keys[keyAutoConfigURL] = autoConfigURL
	}

	// lpszProxy is every scheme in one string; parseProxyServer is where that
	// is taken apart. WinHTTP has already gated it on ProxyEnable, so an entry
	// being present here means the system will actually use it — which is what
	// makes "Enable" answerable at all.
	list := parseProxyServer(proxy)
	for _, m := range schemeToScutil {
		e, ok := findProxyEntry(list, m.scheme)
		st.Keys[m.prefix+"Enable"] = boolKey(ok && e.Host != "")
		if !ok || e.Host == "" {
			continue
		}
		st.Keys[m.prefix+"Proxy"] = e.Host
		// A port key is written only when the string carried a parseable one.
		// Substituting 80 (or 1080) for a missing port would be inventing
		// evidence: ProxyState.Int would then answer ok for a port nobody
		// configured, and checkProxyPair would compare our port against a
		// number this package made up.
		if e.Port != 0 {
			st.Keys[m.prefix+"Port"] = strconv.Itoa(e.Port)
		}
	}

	st.Exceptions = parseBypassList(bypass)
	return st
}

func boolKey(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// parseBypassList splits lpszProxyBypass into scutil's ExceptionsList. Windows
// separates entries with semicolons (and tolerates whitespace); the "<local>"
// token is passed through verbatim rather than expanded, because it is what
// the user configured and doctor prints it back to them.
func parseBypassList(s string) []string {
	out := strings.FieldsFunc(s, isProxyListSeparator)
	if len(out) == 0 {
		return nil
	}
	return out
}

// The scheme tokens Windows uses inside ProxyServer / lpszProxy. They are
// matched case-insensitively on the way in and emitted lower-case.
const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
	schemeFTP   = "ftp"
	schemeSOCKS = "socks"
)

// bareProxySchemes is what a scheme-less entry covers.
//
// It deliberately excludes socks. IE's own "use the same proxy server for all
// protocols" writes the bare form and leaves the Socks row separate, and
// WinHTTP — which is what Live reads through — does not speak SOCKS at all. So
// publishing a SOCKSProxy key derived from a bare entry would claim a SOCKS
// proxy the system will not actually use, and on the write side it would let a
// SOCKS restore silently rewrite the user's HTTP proxy.
var bareProxySchemes = []string{schemeHTTP, schemeHTTPS, schemeFTP}

// proxySchemeOrder is the canonical emit order, so formatProxyServer is
// deterministic and therefore testable. Schemes outside it keep their
// first-seen relative order after these.
var proxySchemeOrder = []string{schemeHTTP, schemeHTTPS, schemeFTP, schemeSOCKS}

// proxyEntry is one scheme's proxy out of a Windows ProxyServer string.
//
// Port 0 means "the string carried no parseable port", not "port zero" — zero
// is not a usable proxy port, so the two cannot be confused, and keeping it as
// a plain int lets ProxySettings round-trip it unchanged.
type proxyEntry struct {
	Scheme string
	Host   string
	Port   int
	// Bare records PROVENANCE: this entry was SYNTHESIZED by parseProxyServer
	// from a scheme-less ("bare") ProxyServer token, not written by the user
	// as "<scheme>=...". It is not decoration — two decisions read it, and
	// both were wrong before it existed:
	//
	//   - hasUndescribedProxy must not mistake the invented ftp entry for a
	//     second, untouched user proxy, because doing so leaves ProxyEnable
	//     switched ON for a user who had it OFF. See decideProxyEnable.
	//   - formatProxyServer must re-emit the bare token as a bare token. A
	//     bare value means "this proxy, for every protocol"; writing it back
	//     out as "http=X;https=X;ftp=X" silently NARROWS it to three, changes
	//     what the IE dialog shows the user ("use the same proxy server for
	//     all protocols" quietly unticks), and makes a restore that is meant
	//     to be byte-identical not be.
	//
	// It is deliberately NOT read by Configured or proxyStateFromIE: a bare
	// token really is the effective http and https proxy, which is precisely
	// what a capture and a verify need to know.
	Bare bool
}

// value renders the entry's host:port half.
func (e proxyEntry) value() string {
	if e.Port == 0 {
		return e.Host
	}
	return e.Host + ":" + strconv.Itoa(e.Port)
}

func isProxyListSeparator(r rune) bool { return r == ';' || unicode.IsSpace(r) }

// parseProxyServer takes apart a Windows proxy list.
//
// MSDN gives the grammar as
// "([<scheme>=][<scheme>"://"]<server>[":"<port>][";"...])" — see
// WINHTTP_PROXY_INFO's lpszProxy — so all of these are legal and all of them
// appear in the wild:
//
//	10.0.0.1:8080                          a bare entry: the default for every scheme
//	http=a:8080;https=b:8443;socks=c:1080   the per-scheme form IE writes
//	http=http://a:8080                      a scheme prefix inside the value
//	[::1]:8080                              an IPv6 literal
//
// A bare entry applies ONLY to schemes not named explicitly, wherever it sits
// in the string. That is why this is two passes rather than one "last wins"
// loop: "http=a:1;b:2" means http goes to a and everything else to b, and a
// single loop would have b overwrite http on the way past.
//
// The entries the bare pass invents are marked proxyEntry.Bare — see that
// field for the two decisions that must be able to tell an invented entry from
// one the user wrote, and what it costs when they cannot.
//
// A host keeps its brackets ("[::1]"), so that a value read here and written
// back by Restore is byte-identical to what the user had.
func parseProxyServer(s string) []proxyEntry {
	var out []proxyEntry
	bare := ""
	sawBare := false

	for _, tok := range strings.FieldsFunc(s, isProxyListSeparator) {
		scheme, value, hasScheme := strings.Cut(tok, "=")
		if !hasScheme {
			value, scheme = scheme, ""
		}
		scheme = strings.ToLower(strings.TrimSpace(scheme))
		value = strings.TrimSpace(value)
		// "http=http://a:8080" — drop the redundant scheme prefix inside the
		// value, and the trailing slash a copy-pasted URL brings with it.
		if i := strings.Index(value, "://"); i >= 0 {
			value = value[i+len("://"):]
		}
		value = strings.TrimSuffix(value, "/")
		if value == "" {
			continue
		}
		if scheme == "" {
			bare, sawBare = value, true
			continue
		}
		host, port := splitProxyHostPort(value)
		out = setProxyEntry(out, proxyEntry{Scheme: scheme, Host: host, Port: port})
	}

	if sawBare {
		host, port := splitProxyHostPort(bare)
		for _, scheme := range bareProxySchemes {
			if _, ok := findProxyEntry(out, scheme); ok {
				continue
			}
			out = append(out, proxyEntry{Scheme: scheme, Host: host, Port: port, Bare: true})
		}
	}
	return out
}

// splitProxyHostPort splits "host:port" without net.SplitHostPort's insistence
// on well-formed input: this parses a string the USER typed into a Windows
// dialog years ago, and anything it cannot read as a port stays part of the
// host so that re-emitting the entry gives the bytes back unchanged.
func splitProxyHostPort(v string) (host string, port int) {
	if strings.HasPrefix(v, "[") {
		if i := strings.Index(v, "]"); i >= 0 {
			rest := v[i+1:]
			if rest == "" {
				return v, 0
			}
			if n, ok := parseProxyPort(strings.TrimPrefix(rest, ":")); ok && strings.HasPrefix(rest, ":") {
				return v[:i+1], n
			}
		}
		return v, 0
	}
	// An unbracketed IPv6 literal ("::1") has more than one colon and no port;
	// splitting on the last one would read "::1" as host "::" port 1.
	if strings.Count(v, ":") != 1 {
		return v, 0
	}
	i := strings.LastIndex(v, ":")
	if n, ok := parseProxyPort(v[i+1:]); ok {
		return v[:i], n
	}
	return v, 0
}

func parseProxyPort(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 65535 {
		return 0, false
	}
	return n, true
}

// formatProxyServer re-emits the list Windows will store. Entries the USER
// wrote are emitted in the explicit scheme= form, in proxySchemeOrder so the
// result is deterministic and therefore assertable.
//
// Entries parseProxyServer SYNTHESIZED from a bare token (proxyEntry.Bare) are
// emitted as the one bare token they came from, not as three explicit entries.
// Expanding them would look harmless and is not: a bare value is the user's
// "use the same proxy server for all protocols", it covers every scheme
// INCLUDING ones this package does not model, and rewriting it as
// "http=X;https=X;ftp=X" narrows it, permanently, on a machine we promised to
// put back. Mixing the two forms in one string is MSDN's own grammar
// ("([<scheme>=][<scheme>"://"]<server>[":"<port>][";"...])") and is exactly
// what parseProxyServer's two-pass rule reads back: explicit entries win, and
// the bare token covers whatever is left.
//
// The collapse case exists so a full apply/revert cycle gives the bytes back.
// After Restore has written the captured host back onto http and https, a
// machine that started with "proxy.corp:8080" holds explicit entries whose
// value is identical to the surviving bare token's; emitting
// "http=proxy.corp:8080;https=proxy.corp:8080;proxy.corp:8080" would say the
// same thing in a shape the user never had and the IE dialog renders
// differently. Collapsing is safe only when every explicit entry both matches
// the bare value AND names a scheme the bare token already covers — a socks
// entry never qualifies, because bareProxySchemes deliberately excludes socks.
func formatProxyServer(list []proxyEntry) string {
	bare, hasBare := findBareProxyEntry(list)
	if hasBare && collapsesToBare(list, bare) {
		return bare.value()
	}

	var parts []string
	emitted := make(map[string]bool, len(list))
	for _, scheme := range proxySchemeOrder {
		if e, ok := findProxyEntry(list, scheme); ok && !e.Bare {
			parts = append(parts, e.Scheme+"="+e.value())
			emitted[scheme] = true
		}
	}
	for _, e := range list {
		if e.Bare || emitted[e.Scheme] {
			continue
		}
		parts = append(parts, e.Scheme+"="+e.value())
	}
	if hasBare {
		// Last, so the explicit entries read first; position carries no
		// meaning in this grammar (see parseProxyServer's two-pass rule).
		parts = append(parts, bare.value())
	}
	return strings.Join(parts, ";")
}

// findBareProxyEntry returns the first synthesized entry. Every synthesized
// entry in a list comes from the SAME bare token and therefore carries the
// same host and port, so the first one is the token.
func findBareProxyEntry(list []proxyEntry) (proxyEntry, bool) {
	for _, e := range list {
		if e.Bare {
			return e, true
		}
	}
	return proxyEntry{}, false
}

// collapsesToBare reports whether list says exactly what the single bare token
// says. See formatProxyServer for why that matters and what disqualifies it.
func collapsesToBare(list []proxyEntry, bare proxyEntry) bool {
	for _, e := range list {
		if e.Bare {
			continue
		}
		if !containsScheme(bareProxySchemes, e.Scheme) || e.value() != bare.value() {
			return false
		}
	}
	return true
}

func findProxyEntry(list []proxyEntry, scheme string) (proxyEntry, bool) {
	for _, e := range list {
		if e.Scheme == scheme {
			return e, true
		}
	}
	return proxyEntry{}, false
}

// setProxyEntry replaces e's scheme in place, keeping its position, or appends
// it. Position is preserved so that a value the user arranged one way does not
// come back rearranged for no reason.
func setProxyEntry(list []proxyEntry, e proxyEntry) []proxyEntry {
	for i := range list {
		if list[i].Scheme == e.Scheme {
			list[i] = e
			return list
		}
	}
	return append(list, e)
}

// removeProxyEntry drops scheme's entry.
//
// Removing a SYNTHESIZED entry also materialises the rest of the bare group as
// explicit entries. A bare token covers every scheme not named explicitly, so
// re-emitting it while claiming to have removed one of the schemes it covers
// would put the removed scheme straight back — formatProxyServer would write
// the token, parseProxyServer would expand it again, and the entry this call
// was asked to delete would be alive on the next read. Writing the survivors
// out per-scheme is the only shape ProxyServer has that says "these protocols,
// not that one", and narrowing the user's value is the lesser harm when the
// alternative is not honouring a removal at all.
func removeProxyEntry(list []proxyEntry, scheme string) []proxyEntry {
	removedBare := false
	out := list[:0]
	for _, e := range list {
		if e.Scheme == scheme {
			removedBare = removedBare || e.Bare
			continue
		}
		out = append(out, e)
	}
	if removedBare {
		for i := range out {
			out[i].Bare = false
		}
	}
	return out
}

// allProxyKinds is what a whole-service capture describes.
var allProxyKinds = []sysport.ProxyKind{sysport.ProxyAuto, sysport.ProxyWeb, sysport.ProxySOCKS}

// proxyWants reports whether p describes kind. A nil Kinds means the capture
// was whole-service, which is what Configured returns; Restore refuses that
// case before it ever reaches here.
func proxyWants(p sysport.ProxySettings, kind sysport.ProxyKind) bool {
	if p.Kinds == nil {
		return true
	}
	for _, k := range p.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// openInternetSettings opens the key for reading and writing. CreateKey rather
// than OpenKey: it opens the existing key on every real Windows install, and
// on the one where the key is somehow absent it makes it rather than failing a
// revert the user needs.
func openInternetSettings() (registry.Key, error) {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return 0, fmt.Errorf("netstate: open HKCU\\%s for writing: %w", internetSettingsKey, err)
	}
	return key, nil
}

// regString reads a REG_SZ value, reading absence as "".
func regString(key registry.Key, name string) (string, error) {
	v, _, err := key.GetStringValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("netstate: read %s: %w", name, err)
	}
	return v, nil
}

// readProxyServer reads the global switch and the packed per-scheme string
// together, because neither means anything without the other: a ProxyServer
// behind ProxyEnable = 0 is configured but inert, which is precisely the state
// ProxySettings records as host set / on false.
func readProxyServer(key registry.Key) (on bool, list []proxyEntry, err error) {
	n, _, err := key.GetIntegerValue(valProxyEnable)
	switch {
	case errors.Is(err, registry.ErrNotExist):
		n = 0
	case err != nil:
		return false, nil, fmt.Errorf("netstate: read %s: %w", valProxyEnable, err)
	}
	s, err := regString(key, valProxyServer)
	if err != nil {
		return false, nil, err
	}
	return n != 0, parseProxyServer(s), nil
}

// notifyProxyChanged pushes the registry change out to processes that are
// already running.
//
// Without it the write is real but invisible: wininet and everything layered
// on it (Edge, Chrome, Electron, .NET's default WebProxy) cache the proxy
// configuration at startup and re-read it only when told. INTERNET_OPTION_
// SETTINGS_CHANGED announces that the settings moved, INTERNET_OPTION_REFRESH
// makes wininet re-read them from the registry, and MSDN's own guidance is to
// send them in that order.
//
// A failure here is returned rather than logged, and the distinction matters:
// Live reads the registry back through WinHTTP fresh on every call, so a
// silently-failed notification would let Verify pass while not one running
// program is actually proxied.
func notifyProxyChanged() error {
	if err := InternetSetOptionW(0, internetOptionSettingsChanged, nil, 0); err != nil {
		return fmt.Errorf("netstate: INTERNET_OPTION_SETTINGS_CHANGED: %w", err)
	}
	if err := InternetSetOptionW(0, internetOptionRefresh, nil, 0); err != nil {
		return fmt.Errorf("netstate: INTERNET_OPTION_REFRESH: %w", err)
	}
	return nil
}
