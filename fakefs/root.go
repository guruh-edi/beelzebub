package fakefs

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

var (
	actualRoot string
	mountPath  string
)

type fakeFS struct {
	fs.Inode
	actualRoot string
	mountPath  string
}

func newFakeFS(actualRoot string, mountPath string) *fakeFS {
	return &fakeFS{
		actualRoot: actualRoot,
		mountPath:  mountPath,
	}
}

var (
	_ = (fs.NodeGetattrer)((*fakeFile)(nil))
	_ = (fs.NodeReader)((*fakeFile)(nil))
	_ = (fs.NodeOpener)((*fakeFile)(nil))
	_ = (fs.InodeEmbedder)((*fakeFile)(nil))
)

type fakeFile struct {
	fs.Inode
	actualPath string
	mu         sync.Mutex
}

func (f *fakeFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	f.mu.Lock()
	defer f.mu.Unlock()

	// info, err := os.Lstat(f.actualPath)
	// if err != nil {
	// 	return syscall.ENOENT
	// }

	out.Size = 0
	out.Mode = 0o644

	return 0
}

func (f *fakeFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	file, err := os.Open(f.actualPath)
	if err != nil {
		errno, ok := err.(syscall.Errno)
		if ok {
			return fuse.ReadResultData(dest), errno
		}
		return fuse.ReadResultData(dest), syscall.ENOENT
	}

	_, err = file.Seek(off, io.SeekStart)
	if err != nil {
		return fuse.ReadResultData(dest), syscall.ENOENT
	}

	_, err = file.Read(dest)
	if err != nil {
		errno, ok := err.(syscall.Errno)
		if ok {
			return fuse.ReadResultData(dest), errno
		}
		return fuse.ReadResultData(dest), syscall.ENOENT
	}

	return fuse.ReadResultData(dest), 0
}

func (f *fakeFile) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	return nil, 0, 0
}

// func (f *fakeFile) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
// 	// no-op
// 	return 0
// }

// func createNode(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (node *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
// 	return nil, nil, 0, syscall.ENOENT
// }

// _ = (fs.NodeLookuper)((*fakeNode)(nil))
// _ = (fs.NodeOnAdder)((*fakeNode)(nil))

// func (n *fakeNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
// 	ops := fakeNode{}
// 	return n.NewInode(ctx, &ops, fs.StableAttr{Mode: syscall.S_IFREG}), 0
// }
//
// func (n *fakeNode) OnAdd(ctx context.Context) {
// }

func InitFakeFS() error {
	flag.StringVar(&actualRoot, "actual", "/opt/honeypot/actual-root", "Actual root directory")
	flag.StringVar(&mountPath, "mount-path", "/opt/honeypot/mnt", "Mount path")
	flag.Parse()

	log.Printf("Using actual root path: %s", actualRoot)
	log.Printf("Mounting at: %s", mountPath)

	root := newFakeFS(actualRoot, mountPath)
	server, err := fs.Mount(mountPath, root, &fs.Options{})
	if err != nil {
		log.Fatalf("Error occured during fs mount: %v", err)
	}
	log.Printf("FS mounted at %s", mountPath)

	server.Wait()
	return nil
}
