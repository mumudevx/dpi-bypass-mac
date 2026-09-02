package netwatch

import "time"

// SleepDetector turns two clocks into a "the lid was closed" signal.
//
// A laptop that sleeps is not a laptop whose network timed out, and the
// difference matters: on wake, every upstream socket is dead, every DNS answer
// may be from a resolver that is no longer reachable, and the routes we
// applied may have been flushed. Treating that as a timeout means discovering
// it one failed connection at a time.
//
// The mechanism is the divergence between two clocks. On darwin Go's monotonic
// reading comes from mach_absolute_time, which does not advance while the
// machine is asleep; the wall clock does. So over one ticker interval:
//
//	gap = (wall_now - wall_prev) - (mono_now - mono_prev)
//
// and a gap larger than Gap means the machine spent that long not running.
//
// It is ADVISORY and never load-bearing (docs/PLAN.md's exit-path table says
// so explicitly): the primary wake signal is the routing-socket churn macOS
// produces when the interfaces come back, and this only makes recovery faster
// when that churn is late or absent. Both ways of being wrong are safe. If the
// platform's monotonic clock did advance through sleep, the detector reports
// nothing and the routing socket carries the day. If NTP steps the wall clock
// forward while awake, the detector reports a sleep that did not happen and
// the process pays for one revalidation that finds nothing changed.
type SleepDetector struct {
	// Gap is the divergence that counts as sleep. Zero means DefaultSleepGap.
	// The plan's number is 10 s, chosen to sit far above scheduler jitter and
	// far below any sleep a user would notice.
	Gap time.Duration

	prev    Instant
	started bool
}

// Reset makes now the baseline without reporting a gap. It is called once
// before the ticker starts, so the first tick measures one interval rather
// than the time since the zero value of time.Time.
func (d *SleepDetector) Reset(now Instant) {
	d.prev = now
	d.started = true
}

// Observe records a sample and reports the sleep it implies, or zero.
//
// A negative divergence — the wall clock stepped backwards, which is what an
// NTP correction after a long uptime looks like — is not sleep and is not
// reported. The baseline moves to the new sample either way, so one clock step
// cannot leave the detector permanently convinced it is asleep.
func (d *SleepDetector) Observe(now Instant) time.Duration {
	if !d.started {
		d.Reset(now)
		return 0
	}
	prev := d.prev
	d.prev = now

	wall := now.Wall.Sub(prev.Wall)
	mono := now.Mono.Sub(prev.Mono)
	gap := wall - mono

	threshold := d.Gap
	if threshold <= 0 {
		threshold = DefaultSleepGap
	}
	if gap < threshold {
		return 0
	}
	return gap
}
