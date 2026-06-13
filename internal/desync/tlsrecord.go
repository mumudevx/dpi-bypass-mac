package desync

import (
	"context"
	"encoding/binary"
)

// tlsRecordFrag re-frames a single TLS handshake record into two records with
// the same content-type and version. This defeats DPI that reassembles TCP
// segments but inspects only the first TLS record. When the input is not a
// complete TLS record it falls back to a plain TCP-level split so the stream is
// never corrupted.
type tlsRecordFrag struct{ window int }

func (tlsRecordFrag) Name() string { return "tls-record-frag" }

func (s tlsRecordFrag) Emit(_ context.Context, conn Conn, data []byte, meta *Meta) error {
	if len(data) < 6 || data[0] != recordTypeHandshake {
		return writeChunks(conn, data, []int{defaultSplit(len(data), s.window)})
	}
	recLen, complete := recordLength(data)
	if !complete {
		return writeChunks(conn, data, []int{defaultSplit(len(data), s.window)})
	}

	recType := data[0]
	ver := data[1:3]
	payload := data[5 : 5+recLen]
	remainder := data[5+recLen:]

	// Prefer splitting inside the SNI (offset is relative to the record
	// payload, i.e. minus the 5-byte header).
	off := s.window
	if meta.SNIOffset > 5 {
		off = (meta.SNIOffset - 5) + meta.SNILen/2
	}
	if off <= 0 || off >= len(payload) {
		off = len(payload) / 2
	}
	if off <= 0 { // payload too small to fragment; send as-is
		_, err := conn.Write(data)
		return err
	}

	if _, err := conn.Write(buildRecord(recType, ver, payload[:off])); err != nil {
		return err
	}
	if _, err := conn.Write(buildRecord(recType, ver, payload[off:])); err != nil {
		return err
	}
	if len(remainder) > 0 {
		if _, err := conn.Write(remainder); err != nil {
			return err
		}
	}
	return nil
}

// buildRecord frames payload as a TLS record with the given type and version.
func buildRecord(recType byte, ver, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = recType
	out[1], out[2] = ver[0], ver[1]
	binary.BigEndian.PutUint16(out[3:5], uint16(len(payload)))
	copy(out[5:], payload)
	return out
}
