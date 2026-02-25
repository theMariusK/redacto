package main

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// Default binary extensions to skip (no redaction/rehydration).
var defaultSkipExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true,
	".ico": true, ".webp": true, ".svg": true, ".tiff": true,
	".zip": true, ".gz": true, ".bz2": true, ".xz": true, ".zst": true,
	".tar": true, ".rar": true, ".7z": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".o": true,
	".a": true, ".lib": true,
	".wasm": true, ".pdf": true, ".sqlite": true, ".db": true,
	".class": true, ".pyc": true, ".pyo": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mkv": true, ".mov": true,
	".wav": true, ".flac": true, ".ogg": true,
	".ttf": true, ".otf": true, ".woff": true, ".woff2": true, ".eot": true,
}

// RedactRoot holds shared state for the redacting filesystem.
type RedactRoot struct {
	scanner        *Scanner
	skipExtensions map[string]bool
	skipPaths      map[string]bool
	rehydrate      bool
}

// RedactNode extends LoopbackNode to return RedactingFile handles.
type RedactNode struct {
	fs.LoopbackNode
	redactRoot *RedactRoot
}

// Compile-time interface checks.
var _ = (fs.NodeOpener)((*RedactNode)(nil))
var _ = (fs.NodeCreater)((*RedactNode)(nil))

func (n *RedactNode) shouldSkip(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return n.redactRoot.skipExtensions[ext]
}

func (n *RedactNode) shouldSkipPath(relPath string) bool {
	if len(n.redactRoot.skipPaths) == 0 {
		return false
	}
	parts := strings.Split(relPath, "/")
	for _, p := range parts {
		if n.redactRoot.skipPaths[p] {
			return true
		}
	}
	return false
}

func (n *RedactNode) relativePath() string {
	return n.Path(n.Root())
}

func (n *RedactNode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	fh, fuseFlags, errno = n.LoopbackNode.Open(ctx, flags)
	if errno != 0 {
		return nil, 0, errno
	}

	relPath := n.relativePath()
	name := filepath.Base(relPath)

	if n.shouldSkip(name) || n.shouldSkipPath(relPath) {
		return fh, fuseFlags, 0
	}

	// Extract the fd from the loopback file handle via FilePassthroughFder.
	ptFd, ok := fh.(fs.FilePassthroughFder)
	if !ok {
		return fh, fuseFlags, 0
	}
	fd, ok := ptFd.PassthroughFd()
	if !ok {
		return fh, fuseFlags, 0
	}

	return &RedactingFile{
		fd:        fd,
		scanner:   n.redactRoot.scanner,
		rehydrate: n.redactRoot.rehydrate,
	}, fuse.FOPEN_DIRECT_IO, 0
}

func (n *RedactNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	inode, fh, fuseFlags, errno = n.LoopbackNode.Create(ctx, name, flags, mode, out)
	if errno != 0 {
		return nil, nil, 0, errno
	}

	if n.shouldSkip(name) {
		return inode, fh, fuseFlags, 0
	}

	ptFd, ok := fh.(fs.FilePassthroughFder)
	if !ok {
		return inode, fh, fuseFlags, 0
	}
	fd, ok := ptFd.PassthroughFd()
	if !ok {
		return inode, fh, fuseFlags, 0
	}

	return inode, &RedactingFile{
		fd:        fd,
		scanner:   n.redactRoot.scanner,
		rehydrate: n.redactRoot.rehydrate,
	}, fuse.FOPEN_DIRECT_IO, 0
}

// RedactingFile is a file handle that intercepts Read and Write for
// redaction and rehydration. It manages the underlying fd directly.
type RedactingFile struct {
	mu        sync.Mutex
	fd        int
	scanner   *Scanner
	rehydrate bool
}

// Compile-time interface checks.
var _ = (fs.FileHandle)((*RedactingFile)(nil))
var _ = (fs.FileReader)((*RedactingFile)(nil))
var _ = (fs.FileWriter)((*RedactingFile)(nil))
var _ = (fs.FileFlusher)((*RedactingFile)(nil))
var _ = (fs.FileReleaser)((*RedactingFile)(nil))
var _ = (fs.FileGetattrer)((*RedactingFile)(nil))
var _ = (fs.FileSetattrer)((*RedactingFile)(nil))
var _ = (fs.FileFsyncer)((*RedactingFile)(nil))
var _ = (fs.FileLseeker)((*RedactingFile)(nil))

func (f *RedactingFile) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	buf := make([]byte, len(dest))
	n, err := syscall.Pread(f.fd, buf, off)
	if n == 0 {
		if err != nil {
			return nil, fs.ToErrno(err)
		}
		return fuse.ReadResultData(nil), fs.OK
	}

	data := buf[:n]

	// Skip binary content: check for null bytes in the first 512 bytes.
	checkLen := n
	if checkLen > 512 {
		checkLen = 512
	}
	binary := false
	for i := 0; i < checkLen; i++ {
		if data[i] == 0 {
			binary = true
			break
		}
	}

	if !binary {
		f.scanner.Redact(data)
	}

	return fuse.ReadResultData(data), fs.OK
}

func (f *RedactingFile) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	writeData := data
	if f.rehydrate {
		// Copy to avoid modifying the caller's slice.
		scratch := make([]byte, len(data))
		copy(scratch, data)
		f.scanner.Rehydrate(scratch)
		writeData = scratch
	}

	n, err := syscall.Pwrite(f.fd, writeData, off)
	return uint32(n), fs.ToErrno(err)
}

func (f *RedactingFile) Flush(ctx context.Context) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	newFd, err := syscall.Dup(f.fd)
	if err != nil {
		return fs.ToErrno(err)
	}
	return fs.ToErrno(syscall.Close(newFd))
}

func (f *RedactingFile) Release(ctx context.Context) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fd != -1 {
		err := syscall.Close(f.fd)
		f.fd = -1
		return fs.ToErrno(err)
	}
	return syscall.EBADF
}

func (f *RedactingFile) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fs.ToErrno(syscall.Fsync(f.fd))
}

func (f *RedactingFile) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()
	var st syscall.Stat_t
	if err := syscall.Fstat(f.fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	out.FromStat(&st)
	return fs.OK
}

func (f *RedactingFile) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()

	if mode, ok := in.GetMode(); ok {
		if err := syscall.Fchmod(f.fd, mode); err != nil {
			return fs.ToErrno(err)
		}
	}

	uid32, uOk := in.GetUID()
	gid32, gOk := in.GetGID()
	if uOk || gOk {
		uid := -1
		gid := -1
		if uOk {
			uid = int(uid32)
		}
		if gOk {
			gid = int(gid32)
		}
		if err := syscall.Fchown(f.fd, uid, gid); err != nil {
			return fs.ToErrno(err)
		}
	}

	if sz, ok := in.GetSize(); ok {
		if err := syscall.Ftruncate(f.fd, int64(sz)); err != nil {
			return fs.ToErrno(err)
		}
	}

	var st syscall.Stat_t
	if err := syscall.Fstat(f.fd, &st); err != nil {
		return fs.ToErrno(err)
	}
	out.FromStat(&st)
	return fs.OK
}

func (f *RedactingFile) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := syscall.Seek(f.fd, int64(off), int(whence))
	return uint64(n), fs.ToErrno(err)
}

// newRedactFS creates and mounts the redacting FUSE filesystem.
// It returns the fuse.Server (call server.Wait() to block, server.Unmount() to stop).
func newRedactFS(sourceDir, mountDir string, rr *RedactRoot, debug bool) (*fuse.Server, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(sourceDir, &st); err != nil {
		return nil, err
	}

	loopbackRoot := &fs.LoopbackRoot{
		Path: sourceDir,
		Dev:  uint64(st.Dev),
	}

	// Use the NewNode callback to create RedactNodes for every child inode.
	loopbackRoot.NewNode = func(root *fs.LoopbackRoot, parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
		return &RedactNode{
			LoopbackNode: fs.LoopbackNode{RootData: root},
			redactRoot:   rr,
		}
	}

	rootNode := &RedactNode{
		LoopbackNode: fs.LoopbackNode{RootData: loopbackRoot},
		redactRoot:   rr,
	}
	loopbackRoot.RootNode = rootNode

	opts := &fs.Options{}
	opts.MountOptions.FsName = sourceDir
	opts.MountOptions.Name = "redactfs"
	opts.MountOptions.Debug = debug
	opts.NullPermissions = true

	server, err := fs.Mount(mountDir, rootNode, opts)
	if err != nil {
		return nil, err
	}

	return server, nil
}
