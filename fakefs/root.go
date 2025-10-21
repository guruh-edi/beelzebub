package fakefs

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
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
	root       *fs.Inode
}

func newFakeFS(actualRoot string, mountPath string) *fakeFS {
	return &fakeFS{
		actualRoot: actualRoot,
		mountPath:  mountPath,
	}
}

func (ff *fakeFS) OnAdd(ctx context.Context) {
	// no-op
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
	fakeFS     *fakeFS
}

func (f *fakeFile) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	info, err := os.Lstat(f.actualPath)
	if err != nil {
		return syscall.ENOENT
	}
	out.Attr.Mode = uint32(info.Mode())
	out.Attr.Size = uint64(info.Size())
	modTime := info.ModTime()
	out.SetTimes(&modTime, &modTime, &modTime)

	return 0
}

func (f *fakeFile) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var r []byte = make([]byte, 512)

	file, err := os.Open(f.actualPath)
	if err != nil {
		errno, ok := err.(syscall.Errno)
		if ok {
			return fuse.ReadResultData(r), errno
		}
		return fuse.ReadResultData(r), syscall.ENOENT
	}

	_, err = file.Seek(off, io.SeekStart)
	if err != nil {
		return fuse.ReadResultData(r), syscall.ENOENT
	}
	log.Println("actual path: " + f.actualPath)
	log.Println("inode path: " + f.Path(f.fakeFS.root))

	whitelists := []string{
		"mnt/creds.txt",
		"mnt/etc/creds.txt",
	}

	inodePath := f.Path(f.fakeFS.root)

	if slices.Contains(whitelists, inodePath) {
		log.Printf("found: %s\n", inodePath)
	}

	if f.actualPath == "/opt/beelzebub/mnt/creds.txt" ||
		f.actualPath == "/opt/beelzebub/mnt/etc/creds.txt" ||
		f.actualPath == "/home/ediguruh/beelzebub/actual-fs/creds.txt" {
		return fuse.ReadResultData([]byte("not secret")), 0
	}

	_, err = file.Read(r)
	if err != nil {
		errno, ok := err.(syscall.Errno)
		if ok {
			return fuse.ReadResultData(r), errno
		}
		return fuse.ReadResultData(r), syscall.ENOENT
	}

	return fuse.ReadResultData(r), 0
}

func (f *fakeFile) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	return nil, 0, 0
}

type fakeDir struct {
	fs.Inode
	actualPath string
	fakeFS     *fakeFS
}

var (
	_ = (fs.NodeReaddirer)((*fakeDir)(nil))
	_ = (fs.NodeLookuper)((*fakeDir)(nil))
	_ = (fs.NodeGetattrer)((*fakeDir)(nil))
	_ = (fs.InodeEmbedder)((*fakeFile)(nil))
)

func (f *fakeDir) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	dirs, err := os.ReadDir(f.actualPath)
	if err != nil {
		return nil, syscall.ENOENT
	}

	var dirList []fuse.DirEntry
	for _, d := range dirs {
		target := filepath.Join(f.actualPath, d.Name())
		info, err := os.Lstat(target)
		if err != nil {
			continue
		}

		dirList = append(dirList, fuse.DirEntry{
			Name: d.Name(),
			Mode: uint32(info.Mode()),
		})
	}

	return fs.NewListDirStream(dirList), 0
}

func (f *fakeDir) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	target := filepath.Join(f.actualPath, name)
	info, err := os.Lstat(target)
	if err != nil {
		return nil, syscall.ENOENT
	}
	isDir := info.IsDir()
	child := makeNode(target, isDir)
	inode := f.NewInode(ctx, child, fs.StableAttr{
		Mode: uint32(info.Mode()),
		Ino:  uint64(info.ModTime().UnixNano()),
	})
	return inode, 0
}

func (f *fakeDir) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	info, err := os.Lstat(f.actualPath)
	if err != nil {
		return syscall.ENOENT
	}
	out.Attr.Mode = uint32(info.Mode())
	out.Attr.Size = uint64(info.Size())
	modTime := info.ModTime()
	out.SetTimes(&modTime, &modTime, &modTime)

	return 0
}

func makeNode(childPath string, isDir bool) fs.InodeEmbedder {
	if isDir {
		return &fakeDir{actualPath: childPath}
	}
	return &fakeFile{actualPath: childPath}
}

func InitFakeFS() error {
	flag.StringVar(&actualRoot, "actual", "/opt/honeypot/actual-root", "Actual root directory")
	flag.StringVar(&mountPath, "mount-path", "/opt/honeypot/mnt", "Mount path")
	flag.Parse()

	log.Printf("Using actual root path: %s", actualRoot)
	log.Printf("Mounting at: %s", mountPath)

	fakeFS := newFakeFS(actualRoot, mountPath)
	root := &fakeDir{
		fakeFS:     fakeFS,
		actualPath: actualRoot,
	}

	server, err := fs.Mount(mountPath, root, &fs.Options{
		MountOptions: fuse.MountOptions{
			AllowOther: true,
			Debug:      true,
			Name:       "fakemirror",
			FsName:     "fakemirror",
		},
	})
	if err != nil {
		log.Fatalf("Error occured during fs mount: %v", err)
	}
	log.Printf("FS mounted at %s", mountPath)

	server.Wait()
	return nil
}
