// Package transport contains unserved transport predicates. It opens no socket,
// dials no endpoint and cannot activate a production handler.
package transport

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/swarma-witness/config"
	"github.com/relux-works/swarma-witness/wire"
)

const MediaType = "application/vnd.swarma.state-witness.v1+json"

var ErrClose = errors.New("close transport without application frame")

type HTTPFrame struct{ body []byte }

func (f HTTPFrame) Body() []byte { return append([]byte(nil), f.body...) }

// DecodeHTTP checks one fully bounded HTTP message. Streaming read deadlines,
// cancellation and refusal before body allocation remain serving dependencies.
func DecodeHTTP(raw []byte, host string) (HTTPFrame, error) {
	close := func() (HTTPFrame, error) { return HTTPFrame{}, ErrClose }
	if len(raw) > 4096+wire.FrameLimit || host == "" {
		return close()
	}
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 || end+4 > 4096 {
		return close()
	}
	lines := strings.Split(string(raw[:end]), "\r\n")
	if len(lines) < 1 || len(lines[0])+2 > 256 || lines[0] != "POST /witness/v1 HTTP/1.1" || len(lines)-1 > 8 {
		return close()
	}
	headers := map[string]string{}
	for _, line := range lines[1:] {
		if len(line)+2 > 1024 || len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			return close()
		}
		for _, c := range []byte(line) {
			if c > 126 || c < 32 && c != '\t' {
				return close()
			}
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			return close()
		}
		for _, c := range []byte(name) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
				return close()
			}
		}
		name = strings.ToLower(name)
		if _, ok = headers[name]; ok {
			return close()
		}
		value = strings.Trim(value, " \t")
		for _, c := range []byte(value) {
			if c < 32 || c > 126 {
				return close()
			}
		}
		headers[name] = value
		switch name {
		case "host", "content-type", "content-length", "connection", "accept", "user-agent":
		default:
			return close()
		}
	}
	if headers["host"] != host || headers["content-type"] != MediaType || !strings.EqualFold(headers["connection"], "close") {
		return close()
	}
	if a, ok := headers["accept"]; ok && a != MediaType {
		return close()
	}
	if len(headers["user-agent"]) > 256 {
		return close()
	}
	n, e := strconv.Atoi(headers["content-length"])
	if e != nil || n < 1 || n > wire.FrameLimit || strconv.Itoa(n) != headers["content-length"] {
		return close()
	}
	body := raw[end+4:]
	if len(body) != n {
		return close()
	}
	if wire.Correlation(body) == "" {
		return close()
	}
	return HTTPFrame{append([]byte(nil), body...)}, nil
}

// HTTPResponse wraps only an already encoded success or existing WS refusal.
func HTTPResponse(body []byte, id, method string) ([]byte, error) {
	if len(body) == 0 || len(body) > wire.FrameLimit {
		return nil, ErrClose
	}
	if _, e := wire.DecodeResponse(body, id, method); e != nil {
		return nil, ErrClose
	}
	header := "HTTP/1.1 200 OK\r\nContent-Type: " + MediaType + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n"
	return append([]byte(header), body...), nil
}

// ValidateBudget uses measured monotonic durations from a future serving layer;
// no timeout stage grants an extension to the accept-relative deadline.
func ValidateBudget(elapsed, tlsElapsed, headersElapsed, bodyElapsed time.Duration, timeoutMS int64) error {
	if !wire.Integer(timeoutMS, 1, 5000) {
		return wire.Refuse("request_malformed")
	}
	if elapsed < 0 || tlsElapsed < 0 || headersElapsed < 0 || bodyElapsed < 0 || elapsed >= time.Duration(timeoutMS)*time.Millisecond || elapsed >= 5*time.Second || tlsElapsed > 3*time.Second || headersElapsed > time.Second || bodyElapsed > time.Second {
		return wire.Refuse("deadline_exceeded")
	}
	if tlsElapsed+headersElapsed+bodyElapsed > elapsed {
		return wire.Refuse("deadline_exceeded")
	}
	return nil
}

type AdmissionCounts struct {
	Connections, Handshakes, Operations, SourceHandshakes, SourceEntries, HandshakeBytes int
	NewSource                                                                            bool
}

func ValidateAdmission(c AdmissionCounts) error {
	if c.Connections < 0 || c.Handshakes < 0 || c.Operations < 0 || c.SourceHandshakes < 0 || c.SourceEntries < 0 || c.HandshakeBytes < 0 {
		return ErrClose
	}
	if c.Connections >= 128 || c.Handshakes >= 16 || c.Operations >= 16 || c.SourceHandshakes >= 2 || c.NewSource && c.SourceEntries >= 1024 || c.HandshakeBytes > 65536 {
		return ErrClose
	}
	return nil
}

// Handler is deliberately not an http.Handler and has no listener/dispatcher.
// ProductionReady refuses regardless of a syntactically valid configuration.
type Handler struct{ Configuration config.Protected }

func (h Handler) ProductionReady() error { return h.Configuration.ProductionReady() }

// Bucket holds exact nanounit tokens at a monotonic duration. The future
// serving layer owns bounded per-source/principal tables, not this pure model.
type Bucket struct {
	Tokens int64
	Last   time.Duration
}

func fullBucket(burst int64, now time.Duration) Bucket {
	return Bucket{burst * int64(time.Second), now}
}
func charge(b Bucket, now time.Duration, rate, burst int64) (Bucket, bool) {
	cap := burst * int64(time.Second)
	if now < b.Last || now < 0 || b.Last < 0 || b.Tokens < 0 || b.Tokens > cap {
		return b, false
	}
	elapsed := int64(now - b.Last)
	// Clamp before multiplication to avoid an overflow after a long idle period.
	if elapsed >= cap/rate {
		b.Tokens = cap
	} else {
		b.Tokens += elapsed * rate
		if b.Tokens > cap {
			b.Tokens = cap
		}
	}
	b.Last = now
	if b.Tokens < int64(time.Second) {
		return b, false
	}
	b.Tokens -= int64(time.Second)
	return b, true
}

type RateSnapshot struct{ PreauthGlobal, PreauthSource, Peer, Mutation, ApplicationGlobal Bucket }

func FreshRateSnapshot(now time.Duration) RateSnapshot {
	return RateSnapshot{fullBucket(40, now), fullBucket(4, now), fullBucket(40, now), fullBucket(4, now), fullBucket(256, now)}
}

// ChargePreauth charges attempted admissions, including later refusals. A future
// uncorrelated connection closes instead of exposing an application rate code.
func ChargePreauth(s RateSnapshot, now time.Duration) (RateSnapshot, error) {
	var a, b bool
	s.PreauthGlobal, a = charge(s.PreauthGlobal, now, 20, 40)
	s.PreauthSource, b = charge(s.PreauthSource, now, 2, 4)
	if !a || !b {
		return s, ErrClose
	}
	return s, nil
}
func ChargeApplication(s RateSnapshot, now time.Duration, write bool) (RateSnapshot, error) {
	var a, b, c bool
	s.Peer, a = charge(s.Peer, now, 20, 40)
	s.ApplicationGlobal, b = charge(s.ApplicationGlobal, now, 200, 256)
	c = true
	if write {
		s.Mutation, c = charge(s.Mutation, now, 2, 4)
	}
	if !a || !b || !c {
		return s, wire.Refuse("rate_limited")
	}
	return s, nil
}
