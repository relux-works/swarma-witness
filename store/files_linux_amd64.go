package store

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// Linux x86-64 UAPI renameat2, RENAME_NOREPLACE. Other targets fail closed;
// there is no racy stat-then-overwrite or link/unlink substitute.
const sysRenameat2 = 316
const sysOpenat2 = 437

// Kernel-enforced resolution forbids symlinks, magic links, mount crossings
// (including bind mounts on the same device) and escaping the protected dirfd.
func openRelative(dirfd int, name string, flags int, mode uint64) (int, error) {
	p, e := syscall.BytePtrFromString(name)
	if e != nil {
		return -1, e
	}
	how := struct{ Flags, Mode, Resolve uint64 }{uint64(flags), mode, 0x01 | 0x02 | 0x04 | 0x08}
	fd, _, errno := syscall.Syscall6(sysOpenat2, uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func nativeRename(dir *os.File, old, next string, replace bool) error {
	a, e := syscall.BytePtrFromString(old)
	if e != nil {
		return e
	}
	b, e := syscall.BytePtrFromString(next)
	if e != nil {
		return e
	}
	flags := uintptr(1)
	if replace {
		flags = 0
	}
	_, _, errno := syscall.Syscall6(sysRenameat2, dir.Fd(), uintptr(unsafe.Pointer(a)), dir.Fd(), uintptr(unsafe.Pointer(b)), flags, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func openDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, syscall.EINVAL
	}
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts {
		next, e := openRelative(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
		var s syscall.Stat_t
		if e = syscall.Fstat(fd, &s); e != nil || s.Mode&0022 != 0 || s.Uid != 0 && s.Uid != uint32(os.Geteuid()) {
			syscall.Close(fd)
			return nil, syscall.EPERM
		}
	}
	var s syscall.Stat_t
	if e = syscall.Fstat(fd, &s); e != nil || s.Uid != uint32(os.Geteuid()) || s.Mode&0777 != 0700 {
		syscall.Close(fd)
		return nil, syscall.EPERM
	}
	return os.NewFile(uintptr(fd), path), nil
}
func openFile(dir *os.File, name string, create bool) (*os.File, error) {
	if !directoryValid(dir) {
		return nil, syscall.EPERM
	}
	if name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return nil, syscall.EINVAL
	}
	flags := syscall.O_RDONLY
	if create {
		flags = syscall.O_WRONLY | syscall.O_CREAT | syscall.O_EXCL
	}
	mode := uint64(0)
	if create {
		mode = 0600
	}
	fd, e := openRelative(int(dir.Fd()), name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, mode)
	if e != nil {
		return nil, e
	}
	var s, parent syscall.Stat_t
	e = syscall.Fstat(fd, &s)
	pe := syscall.Fstat(int(dir.Fd()), &parent)
	if e != nil || pe != nil || s.Mode&syscall.S_IFMT != syscall.S_IFREG || s.Mode&0777 != 0600 || s.Uid != uint32(os.Geteuid()) || s.Nlink != 1 || s.Dev != parent.Dev {
		syscall.Close(fd)
		return nil, syscall.EPERM
	}
	return os.NewFile(uintptr(fd), name), nil
}
func spaceAvailable(dir *os.File, n int64) bool {
	var s syscall.Statfs_t
	if syscall.Fstatfs(int(dir.Fd()), &s) != nil || s.Bsize <= 0 {
		return false
	}
	return s.Bavail >= uint64((n+s.Bsize-1)/s.Bsize)
}
func directoryValid(dir *os.File) bool {
	var s syscall.Stat_t
	return syscall.Fstat(int(dir.Fd()), &s) == nil && s.Mode&syscall.S_IFMT == syscall.S_IFDIR && s.Mode&0777 == 0700 && s.Uid == uint32(os.Geteuid())
}
