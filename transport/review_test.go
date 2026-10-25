package transport

import (
	"bytes"
	"testing"
)

// Review: field edge OWS remains allowed; an interior control character in
// User-Agent is forbidden by the closed G12 header profile.
func TestReviewHTTPInteriorControl(t *testing.T) {
	valid := httpRequest(request(t, "one"))
	for _, ua := range []string{"ordinary-agent", " \tordinary-agent\t ", "agent\tname"} {
		raw := bytes.Replace(valid, []byte("Connection: close"), []byte("Connection: close\r\nUser-Agent: "+ua), 1)
		_, e := DecodeHTTP(raw, "witness.invalid")
		if ua != "agent\tname" && e != nil {
			t.Fatal("positive control", e)
		}
		if ua == "agent\tname" && e != ErrClose {
			t.Fatalf("interior HTAB accepted: %v", e)
		}
	}
}
