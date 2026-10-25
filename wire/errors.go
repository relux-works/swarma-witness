// Package wire implements bounded canonical values and transport-independent
// carriers. It authenticates no peer and starts no network service.
package wire

import "errors"

// Error contains only a closed code and its fixed retryability.
type Error struct {
	Code      string
	Retryable bool
}

func (e *Error) Error() string { return e.Code }
func Refuse(code string) error {
	r, ok := Retryable(code)
	if !ok {
		return &Error{Code: "request_malformed"}
	}
	return &Error{Code: code, Retryable: r}
}
func Code(e error) string {
	if e == nil {
		return ""
	}
	var w *Error
	if errors.As(e, &w) {
		return w.Code
	}
	return "request_malformed"
}
func Retryable(code string) (bool, bool) {
	switch code {
	case "request_malformed", "limit_exceeded", "not_authorized", "stream_unavailable", "bootstrap_required", "stream_empty", "head_conflict", "position_conflict", "checkpoint_fork", "sequence_exhausted", "profile_unavailable", "proof_limit", "evidence_invalid", "storage_unavailable", "outcome_unknown", "deadline_exceeded":
		return false, true
	case "rate_limited", "busy":
		return true, true
	}
	return false, false
}
