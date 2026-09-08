// Package sysport is the boundary between dpb's system mutations and the
// operating system underneath them.
//
// It is a leaf: it imports nothing else in this module. That is what lets the
// implementations (internal/sysconf/scdarwin, internal/sysconf/scwindows)
// depend on these types while internal/netstate depends on both, with no
// import cycle.
//
// The rule this package exists to make portable is netstate's: verification
// never uses the subsystem that applied the change. Every controller here
// therefore splits its reads in two — one method reading through the writer's
// own subsystem (for capturing state to restore), one reading through a
// different subsystem (for verifying a mutation landed). Collapsing those into
// a single Get is how the rule gets lost.
//
// The rule matters differently on each platform. On macOS the risk is a tool
// that exits 0 while failing, which is why Result carries a liar table. On
// Windows the risk is text: netsh and route.exe emit the system UI language,
// and there is no LC_ALL=C for a child's thread UI language, so the Windows
// implementation parses no output at all.
package sysport
