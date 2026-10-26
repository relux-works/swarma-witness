//go:build linux && swarma_timeconf_fixture && swarma_timeconf_qualification

package qualifiedtime

import "testing"

// TestWindowRealTimeQualification is the real-time settlement qualification gate
// for an exact tuple selected jointly by Keymaker and Research. It runs the same
// real settlement, IO, 300/400 ms budgets and endpoint assertions without a
// synctest bubble. The endpoint/fence/final clock are still synthetic: this does
// not qualify native endpoint enforcement. The tuple is not yet selected or
// qualified; hosted-CI virtual-time results never supply this evidence.
func TestWindowRealTimeQualification(t *testing.T) {
	for _, w := range []Window{P, R, X, TLS} {
		t.Run(string(w), func(t *testing.T) { checkTimelyEndpoint(t, w) })
	}
}
