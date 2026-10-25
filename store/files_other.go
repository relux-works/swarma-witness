//go:build !linux || !amd64

package store

import (
	"os"

	"github.com/relux-works/swarma-witness/wire"
)

func nativeRename(*os.File, string, string, bool) error { return wire.Refuse("profile_unavailable") }
func openDirectory(string) (*os.File, error)            { return nil, wire.Refuse("profile_unavailable") }
func openFile(*os.File, string, bool) (*os.File, error) {
	return nil, wire.Refuse("profile_unavailable")
}
func spaceAvailable(*os.File, int64) bool { return false }
func directoryValid(*os.File) bool        { return false }
