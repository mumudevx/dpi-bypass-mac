package desync

import "context"

// writeChunks writes data to conn split at the given ascending byte offsets,
// one Write call per chunk. Each chunk becomes a separate write syscall; the
// front-end is responsible for TCP_NODELAY so chunks tend to land in separate
// segments. Offsets that are out of range or non-increasing are skipped, so the
// stream content is always preserved exactly.
func writeChunks(conn Conn, data []byte, splits []int) error {
	prev := 0
	for _, s := range splits {
		if s <= prev || s >= len(data) {
			continue
		}
		if _, err := conn.Write(data[prev:s]); err != nil {
			return err
		}
		prev = s
	}
	_, err := conn.Write(data[prev:])
	return err
}

// defaultSplit picks a single split offset from an explicit window, clamped so
// the result yields two non-empty chunks when possible.
func defaultSplit(n, window int) int {
	off := window
	if off <= 0 {
		off = 1
	}
	if off >= n {
		off = n / 2
	}
	return off
}

// splitAtOffset splits at a fixed byte offset (SpoofDPI-style window size).
type splitAtOffset struct{ offset, window int }

func (splitAtOffset) Name() string { return "split-at-offset" }

func (s splitAtOffset) Emit(_ context.Context, conn Conn, data []byte, _ *Meta) error {
	off := s.offset
	if off <= 0 {
		off = defaultSplit(len(data), s.window)
	}
	if off >= len(data) {
		off = len(data) / 2
	}
	return writeChunks(conn, data, []int{off})
}

// splitAtSNI splits inside the SNI host-name so the domain spans two segments,
// defeating DPI that reads only the first segment. Falls back to a window/1-byte
// split when no SNI is present.
type splitAtSNI struct{ window int }

func (splitAtSNI) Name() string { return "split-at-sni" }

func (s splitAtSNI) Emit(_ context.Context, conn Conn, data []byte, meta *Meta) error {
	var off int
	switch {
	case meta.SNIOffset > 0 && meta.SNILen > 0:
		off = meta.SNIOffset + meta.SNILen/2
	case s.window > 0:
		off = s.window
	default:
		off = 1
	}
	if off >= len(data) {
		off = len(data) / 2
	}
	return writeChunks(conn, data, []int{off})
}

// multiSplit splits the payload into several segments at the configured chunk
// sizes (cumulative). With no sizes it degrades to a single window split.
type multiSplit struct {
	sizes  []int
	window int
}

func (multiSplit) Name() string { return "multi-split" }

func (s multiSplit) Emit(_ context.Context, conn Conn, data []byte, _ *Meta) error {
	if len(s.sizes) == 0 {
		return writeChunks(conn, data, []int{defaultSplit(len(data), s.window)})
	}
	var splits []int
	acc := 0
	for _, sz := range s.sizes {
		if sz <= 0 {
			continue
		}
		acc += sz
		if acc >= len(data) {
			break
		}
		splits = append(splits, acc)
	}
	return writeChunks(conn, data, splits)
}
