package tunfe

import (
	"testing"

	"github.com/mumudevx/dpb/internal/front/proxyfe"
)

// TestQUICPolicyIsTheSameInBothFrontEnds pins the two enums together.
//
// The QUIC policy is one thing a user sets, and it must not mean two things in
// the two front ends: a config that reads "quic = desync" cannot desync in the
// tunnel and relay through SOCKS5. They are separate types because proxyfe must
// not import a gVisor netstack to answer a CONNECT — but separate types drift,
// so this test is what stops them.
//
// It lives here rather than in proxyfe because this direction of the import is
// the harmless one: tunfe already depends on the world proxyfe depends on.
//
// If a third policy value is ever added, add it in both places and here.
func TestQUICPolicyIsTheSameInBothFrontEnds(t *testing.T) {
	t.Parallel()
	pairs := []struct {
		tun   QUICPolicy
		proxy proxyfe.QUICPolicy
	}{
		{QUICRefuse, proxyfe.QUICRefuse},
		{QUICRelay, proxyfe.QUICRelay},
		{QUICDesync, proxyfe.QUICDesync},
	}
	for _, p := range pairs {
		if uint8(p.tun) != uint8(p.proxy) {
			t.Errorf("value mismatch: tunfe %d vs proxyfe %d", uint8(p.tun), uint8(p.proxy))
		}
		if p.tun.String() != p.proxy.String() {
			t.Errorf("name mismatch for value %d: tunfe %q vs proxyfe %q",
				uint8(p.tun), p.tun.String(), p.proxy.String())
		}
	}
	// And neither side has grown a value the other has not: the last known
	// value must be the last value.
	if QUICPolicy(len(pairs)).String() == proxyfe.QUICPolicy(len(pairs)).String() &&
		QUICPolicy(len(pairs)).String() != "quicpolicy(3)" {
		t.Errorf("both front ends have a policy value %d that this test does not know about", len(pairs))
	}
}
