//go:build !linux

package qualifiedtime

// Windows supplies no native implementation outside Linux. Darwin receipts,
// continuous-clock/domain conversion and namespace/act qualification are absent.
type Windows struct{}

func New() *Windows    { return &Windows{} }
func (*Windows) Stop() {}
