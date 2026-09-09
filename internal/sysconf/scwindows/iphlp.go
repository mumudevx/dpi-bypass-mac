//go:build windows

package scwindows

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file wraps the twelve Win32 procedures golang.org/x/sys/windows@v0.43.0
// does not provide. Everything else scwindows needs — GetIpForwardTable2,
// FreeMibTable, GetAdaptersAddresses, GetIfEntry2Ex, NotifyRouteChange2, and
// the MibIpForwardRow2 / MibUnicastIpAddressRow / MibIpInterfaceRow /
// IpAdapterAddresses struct layouts — already exists there and is used
// directly; it is not re-wrapped here, and none of those struct types are
// redeclared, because a hand-copied layout is exactly how a field offset goes
// silently wrong and corrupts the routing table. Verified against
// golang.org/x/sys@v0.43.0 by reading zsyscall_windows.go and
// types_windows.go before writing this file (see task-1-report.md).
//
// Every LazyDLL below is built with NewLazySystemDLL, never NewLazyDLL.
// windows/dll_windows.go says why in NewLazyDLL's own doc comment: "using
// NewLazyDLL without an absolute path name is subject to DLL preloading
// attacks. To safely load a system DLL, use NewLazySystemDLL." All twelve
// procedures live in DLLs Windows ships in the system directory, so there is
// no reason to accept that risk.
//
// The twelve procedures do NOT share one error convention, and treating them
// as if they did is the mistake this file is written to avoid:
//
//   - The nine iphlpapi.dll procedures are NETIOAPI_API: they return a Win32
//     error code DIRECTLY as their return value. Zero (NO_ERROR) is success;
//     anything else already IS the error, with nothing to fetch from
//     GetLastError. This is the exact convention x/sys/windows' own generated
//     wrappers use for the sibling procedures it does carry — see
//     GetIpForwardTable2 and FreeMibTable in zsyscall_windows.go, both of
//     which test their r0 the same way.
//   - InternetSetOptionW, WinHttpGetIEProxyConfigForCurrentUser and
//     SendMessageTimeoutW return a BOOL or LRESULT where ZERO means failure
//     and the real error comes from GetLastError — which LazyProc.Call
//     already returns as its third value, documented in dll_windows.go:
//     "The returned error is always non-nil, constructed from the result of
//     GetLastError. Callers must inspect the primary return value to decide
//     whether an error occurred ... before consulting the error."
//
// One exception to "returns error": InitializeUnicastIpAddressEntry is void.
// See its wrapper below for why inventing a return value there would be
// worse than no wrapper at all.
var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
	modwininet  = windows.NewLazySystemDLL("wininet.dll")
	modwinhttp  = windows.NewLazySystemDLL("winhttp.dll")
	moduser32   = windows.NewLazySystemDLL("user32.dll")

	// iphlpapi.dll — NETIOAPI_API convention: return value IS the Win32 error
	// code (0 == NO_ERROR == success).
	procCreateIpForwardEntry2           = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2           = modiphlpapi.NewProc("DeleteIpForwardEntry2")
	procGetBestRoute2                   = modiphlpapi.NewProc("GetBestRoute2")
	procCreateUnicastIpAddressEntry     = modiphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procDeleteUnicastIpAddressEntry     = modiphlpapi.NewProc("DeleteUnicastIpAddressEntry")
	procInitializeUnicastIpAddressEntry = modiphlpapi.NewProc("InitializeUnicastIpAddressEntry") // void — see wrapper
	procGetIpInterfaceEntry             = modiphlpapi.NewProc("GetIpInterfaceEntry")
	procSetIpInterfaceEntry             = modiphlpapi.NewProc("SetIpInterfaceEntry")
	procConvertInterfaceLuidToIndex     = modiphlpapi.NewProc("ConvertInterfaceLuidToIndex")

	// wininet.dll / winhttp.dll / user32.dll — BOOL or LRESULT convention:
	// zero means failure, and the error is GetLastError (LazyProc.Call's
	// third return value).
	procInternetSetOptionW                    = modwininet.NewProc("InternetSetOptionW")
	procWinHttpGetIEProxyConfigForCurrentUser = modwinhttp.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	procSendMessageTimeoutW                   = moduser32.NewProc("SendMessageTimeoutW")
)

// CreateIpForwardEntry2 creates a new route in the local computer's IP
// routing table. See
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2
//
// row's layout is windows.MibIpForwardRow2 (x/sys), not redeclared here.
func CreateIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	r0, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if r0 != 0 {
		return windows.Errno(r0)
	}
	return nil
}

// DeleteIpForwardEntry2 deletes a route from the local computer's IP routing
// table. See
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteipforwardentry2
func DeleteIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	r0, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if r0 != 0 {
		return windows.Errno(r0)
	}
	return nil
}

// GetBestRoute2 asks the routing subsystem which route it would actually
// select for destinationAddress, traversing route selection and interface
// state rather than reading a row back verbatim. That is what makes it a
// genuine second opinion on CreateIpForwardEntry2's write — the Windows
// analogue of `route -n get` on macOS — rather than the same write reflected
// through a mirror. See
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2
//
// interfaceLuid and sourceAddress are documented "in, optional" and may be
// nil; pass interfaceIndex 0 with interfaceLuid nil to let the API choose
// unconstrained by interface. destinationAddress, bestRoute and
// bestSourceAddress are required (non-nil).
func GetBestRoute2(
	interfaceLuid *uint64,
	interfaceIndex uint32,
	sourceAddress *windows.RawSockaddrInet,
	destinationAddress *windows.RawSockaddrInet,
	addressSortOptions uint32,
	bestRoute *windows.MibIpForwardRow2,
	bestSourceAddress *windows.RawSockaddrInet,
) error {
	r0, _, _ := procGetBestRoute2.Call(
		uintptr(unsafe.Pointer(interfaceLuid)),
		uintptr(interfaceIndex),
		uintptr(unsafe.Pointer(sourceAddress)),
		uintptr(unsafe.Pointer(destinationAddress)),
		uintptr(addressSortOptions),
		uintptr(unsafe.Pointer(bestRoute)),
		uintptr(unsafe.Pointer(bestSourceAddress)),
	)
	if r0 != 0 {
		return windows.Errno(r0)
	}
	return nil
}

// CreateUnicastIpAddressEntry adds a new unicast IP address entry on the
// local computer. See
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createunicastipaddressentry
//
// row's layout is windows.MibUnicastIpAddressRow (x/sys), not redeclared
// here.
func CreateUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) error {
	r0, _, _ := procCreateUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	if r0 != 0 {
		return windows.Errno(r0)
	}
	return nil
}

// DeleteUnicastIpAddressEntry deletes an existing unicast IP address entry.
// See
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteunicastipaddressentry
func DeleteUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) error {
	r0, _, _ := procDeleteUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	if r0 != 0 {
		return windows.Errno(r0)
	}
	return nil
}

// InitializeUnicastIpAddressEntry fills row with default values for every
// field CreateUnicastIpAddressEntry does not require the caller to set
// explicitly. See
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-initializeunicastipaddressentry
//
// MSDN gives this function's return type as void — there is no error to
// report, because there is nothing it can fail at beyond writing to row.
// A wrapper that invented an error return here would compile, would always
// report success, and would be strictly worse than no wrapper: it is exactly
// the shape of the three defects Plan 2 found (syscall.Sendto returning
// EWINDOWS unconditionally, os.Process.Signal only handling Kill) — a Windows
// API that "looks right" while telling the caller nothing true.
func InitializeUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) {
	procInitializeUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
}

// GetIpInterfaceEntry retrieves IP information for the interface identified
// by row.InterfaceLuid or row.InterfaceIndex (row.Family must also be set;
// see MSDN's "Remarks"). See
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipinterfaceentry
func GetIpInterfaceEntry(row *windows.MibIpInterfaceRow) error {
	r0, _, _ := procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	if r0 != 0 {
		return windows.Errno(r0)
	}
	return nil
}

// SetIpInterfaceEntry sets the properties of an IP interface, most notably
// NlMtu. Callers must first populate row with GetIpInterfaceEntry — MSDN:
// "the caller needs to first call the GetIpInterfaceEntry ... to get the
// current values ... and then set the ... members ... that need to change."
// See
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry
func SetIpInterfaceEntry(row *windows.MibIpInterfaceRow) error {
	r0, _, _ := procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	if r0 != 0 {
		return windows.Errno(r0)
	}
	return nil
}

// ConvertInterfaceLuidToIndex converts a locally unique interface identifier
// (LUID) to its interface index. scwindows needs this because
// sysport.IfaceConfig identifies an interface by NAME, while
// MibIpInterfaceRow and MibUnicastIpAddressRow key on LUID or index — never
// name. See
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoindex
//
// x/sys/windows represents a NET_LUID as a bare uint64 everywhere it appears
// in a struct field (e.g. MibIpForwardRow2.InterfaceLuid); this wrapper keeps
// the same representation rather than introducing a distinct LUID type.
func ConvertInterfaceLuidToIndex(interfaceLuid *uint64, interfaceIndex *uint32) error {
	r0, _, _ := procConvertInterfaceLuidToIndex.Call(
		uintptr(unsafe.Pointer(interfaceLuid)),
		uintptr(unsafe.Pointer(interfaceIndex)),
	)
	if r0 != 0 {
		return windows.Errno(r0)
	}
	return nil
}

// InternetSetOptionW sets an Internet option. Plan 3 Task 4 calls this with
// hInternet 0 for the two global, handle-less options
// INTERNET_OPTION_SETTINGS_CHANGED and INTERNET_OPTION_REFRESH after writing
// the proxy registry keys directly, because a registry write alone does not
// reach already-running processes. See
// https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetsetoptionw
//
// wininet convention: BOOL return, zero means failure and the error is
// GetLastError — already surfaced as Call's third return value.
func InternetSetOptionW(hInternet uintptr, option uint32, buffer unsafe.Pointer, bufferLen uint32) error {
	r0, _, err := procInternetSetOptionW.Call(hInternet, uintptr(option), uintptr(buffer), uintptr(bufferLen))
	if r0 == 0 {
		return err
	}
	return nil
}

// WinHttpGetIEProxyConfigForCurrentUser fills pProxyConfig — a
// WINHTTP_CURRENT_USER_IE_PROXY_CONFIG { BOOL fAutoDetect; LPWSTR
// lpszAutoConfigUrl; LPWSTR lpszProxy; LPWSTR lpszProxyBypass; } — with the
// current user's IE proxy settings. See
// https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpgetieproxyconfigforcurrentuser
//
// x/sys/windows does not define that struct, so this wrapper stays untyped
// (unsafe.Pointer) rather than hand-copying a layout that has no maintained
// source to check it against — the same reasoning this file's package
// comment gives for not redeclaring MibIpForwardRow2 and friends. The caller
// (scwindows's proxy.go, Plan 3 Task 4) owns that struct's definition and, per
// MSDN, "must free the strings ... using the GlobalFree function" — the
// three LPWSTR fields, not the struct itself.
//
// winhttp convention: BOOL return, zero means failure and the error is
// GetLastError — already surfaced as Call's third return value.
func WinHttpGetIEProxyConfigForCurrentUser(pProxyConfig unsafe.Pointer) error {
	r0, _, err := procWinHttpGetIEProxyConfigForCurrentUser.Call(uintptr(pProxyConfig))
	if r0 == 0 {
		return err
	}
	return nil
}

// SendMessageTimeoutW sends a message to hWnd's window procedure and gives up
// after timeout milliseconds, so a hung window cannot stall teardown. Plan 3
// Task 5 broadcasts WM_SETTINGCHANGE with hWnd = HWND_BROADCAST after writing
// HKCU\Environment, so already-running processes with a message loop notice
// the change; new child processes pick it up from the registry regardless.
// See
// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagetimeoutw
//
// user32 convention here: LRESULT return, and MSDN is explicit that zero
// covers BOTH failure and timeout — "If the function fails or times out, the
// return value is 0. To get extended error information, call GetLastError.
// If GetLastError returns ERROR_TIMEOUT, then the function timed out." Either
// way the error is GetLastError, already surfaced as Call's third return
// value.
func SendMessageTimeoutW(hWnd uintptr, msg uint32, wParam, lParam uintptr, flags, timeout uint32, result *uintptr) error {
	r0, _, err := procSendMessageTimeoutW.Call(
		hWnd,
		uintptr(msg),
		wParam,
		lParam,
		uintptr(flags),
		uintptr(timeout),
		uintptr(unsafe.Pointer(result)),
	)
	if r0 == 0 {
		return err
	}
	return nil
}
