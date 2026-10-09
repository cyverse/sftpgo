//go:build !noirods
// +build !noirods

package vfs

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/metric"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"

	irodsfs "github.com/cyverse/go-irodsclient/fs"
	irodstypes "github.com/cyverse/go-irodsclient/irods/types"
)

const (
	irodsReadSize  int = 128 * 1024      // 128KB
	irodsWriteSize int = 8 * 1024 * 1024 // 8MB
)

// IRODSFs is a Fs implementation for iRODS backends
type IRODSFs struct {
	connectionID string
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath    string
	localTempDir string
	config       *IRODSFsConfig
	irodsClient  *irodsfs.FileSystem
}

func init() {
	version.AddFeature("+irods")
}

// NewIRODSFs returns an IRODSFs object that allows to interact with an iRODS
func NewIRODSFs(connectionID, localTempDir, mountPath string, irodsConfig IRODSFsConfig) (Fs, error) {
	if localTempDir == "" {
		localTempDir = getLocalTempDir()
	}
	fs := &IRODSFs{
		connectionID: connectionID,
		localTempDir: localTempDir,
		mountPath:    getMountPath(mountPath),
		config:       &irodsConfig,
	}
	if err := fs.config.validate(); err != nil {
		return fs, err
	}

	fsLog(fs, logger.LevelDebug, "creating a new iRODS Fs connID: %s, localTempDir: %s, mountPath: %s\n    iRODS Host: %s, Auth: %s, Collection Path: %s", fs.connectionID, fs.localTempDir, fs.mountPath, fs.config.Endpoint, fs.config.AuthScheme, fs.config.CollectionPath)

	if !fs.config.Password.IsEmpty() {
		if err := fs.config.Password.TryDecrypt(); err != nil {
			return nil, err
		}
	}

	fs.setConfigDefaults()

	err := fs.createConnection()
	return fs, err
}

// Name returns the name for the Fs implementation
func (fs *IRODSFs) Name() string {
	return fmt.Sprintf("%s endpoint %q", irodsFsName, fs.config.Endpoint)
}

// ConnectionID returns the connection ID associated to this Fs implementation
func (fs *IRODSFs) ConnectionID() string {
	return fs.connectionID
}

// Stat returns a FileInfo describing the named file
func (fs *IRODSFs) Stat(name string) (os.FileInfo, error) {
	if fs.irodsClient == nil {
		// not connected yet
		return nil, fmt.Errorf("irods client is not connected yet")
	}

	irodsPath := fs.getIRODSPath(name)
	entry, err := fs.irodsClient.Stat(irodsPath)
	if err != nil {
		return nil, err
	}

	fileinfo := fs.makeFileInfoFromEntry(entry)
	return fileinfo, nil
}

// Lstat returns a FileInfo describing the named file
func (fs *IRODSFs) Lstat(name string) (os.FileInfo, error) {
	return fs.Stat(name)
}

// Open opens the named file for reading
func (fs *IRODSFs) Open(name string, offset int64) (File, PipeReader, func(), error) {
	if fs.irodsClient == nil {
		// not connected yet
		return nil, nil, nil, fmt.Errorf("irods client is not connected yet")
	}

	irodsPath := fs.getIRODSPath(name)

	fsLog(fs, logger.LevelDebug, "opening a file %s", irodsPath)

	irodsFileHandle, err := fs.irodsClient.OpenFile(irodsPath, "", string(irodstypes.FileOpenModeReadOnly))
	if err != nil {
		return nil, nil, nil, err
	}

	if offset > 0 {
		_, err = irodsFileHandle.Seek(offset, io.SeekStart)
		if err != nil {
			irodsFileHandle.Close()
			return nil, nil, nil, err
		}
	}

	// the pipe is created after opening the file, closing the writer
	// on error would block until the reader is closed
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		irodsFileHandle.Close()
		return nil, nil, nil, err
	}
	p := NewPipeReader(r)

	go func() {
		//n, err := fs.copy(w, irodsFileHandle, irodsReadSize)
		n, err := io.Copy(w, irodsFileHandle)
		w.CloseWithError(err) //nolint:errcheck
		irodsFileHandle.Close()
		fsLog(fs, logger.LevelDebug, "download completed, path: %q size: %v, err: %+v", irodsPath, n, err)
		metric.IRODSFsTransferCompleted(n, 1, err)
	}()
	return nil, p, nil, nil
}

// Create creates or opens the named file for writing
func (fs *IRODSFs) Create(name string, flag, checks int) (File, PipeWriter, func(), error) {
	if fs.irodsClient == nil {
		// not connected yet
		return nil, nil, nil, fmt.Errorf("irods client is not connected yet")
	}

	if checks&CheckParentDir != 0 {
		_, err := fs.Stat(path.Dir(name))
		if err != nil {
			return nil, nil, nil, err
		}
	}

	irodsPath := fs.getIRODSPath(name)

	var irodsFileHandle *irodsfs.FileHandle
	var err error
	if fs.irodsClient.ExistsFile(irodsPath) {
		// open
		fsLog(fs, logger.LevelDebug, "opening a file %s", irodsPath)
		irodsFileHandle, err = fs.irodsClient.OpenFile(irodsPath, "", string(irodstypes.FileOpenModeWriteTruncate))
	} else {
		// create
		fsLog(fs, logger.LevelDebug, "creating a file %s", irodsPath)
		irodsFileHandle, err = fs.irodsClient.CreateFile(irodsPath, "", string(irodstypes.FileOpenModeWriteOnly))
	}

	if err != nil {
		return nil, nil, nil, err
	}

	// the pipe is created after opening the file, as in Open
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		irodsFileHandle.Close()
		return nil, nil, nil, err
	}
	p := NewPipeWriter(w)

	go func() {
		bw := bufio.NewWriterSize(irodsFileHandle, irodsWriteSize)
		// we don't use io.Copy since bufio.Writer implements io.WriterTo and
		// so it calls the sftp.File WriteTo method without buffering
		n, err := doCopy(bw, r, nil)
		errFlush := bw.Flush()
		if err == nil && errFlush != nil {
			err = errFlush
		}
		errClose := irodsFileHandle.Close()
		if err == nil && errClose != nil {
			err = errClose
		}
		r.CloseWithError(err) //nolint:errcheck
		p.Done(err)
		fsLog(fs, logger.LevelDebug, "upload completed, path: %q, readed bytes: %v, err: %v", irodsPath, n, err)
		metric.IRODSFsTransferCompleted(r.GetReadedBytes(), 0, err)
	}()
	return nil, p, nil, nil
}

// Rename renames (moves) source to target.
func (fs *IRODSFs) Rename(source, target string, checks int) (int, int64, error) {
	if fs.irodsClient == nil {
		// not connected yet
		return -1, -1, fmt.Errorf("irods client is not connected yet")
	}

	if source == target {
		return -1, -1, nil
	}

	if checks&CheckParentDir != 0 {
		_, err := fs.Stat(path.Dir(target))
		if err != nil {
			return -1, -1, err
		}
	}

	sourceIrodsPath := fs.getIRODSPath(source)
	targetIrodsPath := fs.getIRODSPath(target)

	fsLog(fs, logger.LevelDebug, "renaming a file %s ==> %s", sourceIrodsPath, targetIrodsPath)

	entry, err := fs.irodsClient.Stat(sourceIrodsPath)
	if err != nil {
		return -1, -1, err
	}

	if entry.Type == irodsfs.DirectoryEntry {
		// we don't know the number of files and their size, the caller will calculate them if needed
		return -1, -1, fs.irodsClient.RenameDirToDir(sourceIrodsPath, targetIrodsPath)
	}

	targetEntry, err := fs.irodsClient.Stat(targetIrodsPath)
	if err == nil && targetEntry.Type == irodsfs.FileEntry {
		err = fs.overwriteFile(sourceIrodsPath, targetIrodsPath)
	} else {
		err = fs.irodsClient.RenameFileToFile(sourceIrodsPath, targetIrodsPath)
	}
	if err != nil {
		return 0, 0, err
	}
	return 1, entry.Size, nil
}

// overwriteFile renames source to the existing target file. iRODS does not allow to rename
// over an existing data object, so the target is moved to a backup path and restored on error
func (fs *IRODSFs) overwriteFile(sourceIrodsPath, targetIrodsPath string) error {
	backupIrodsPath := fmt.Sprintf("%s.sftpgo-bak-%s", targetIrodsPath, util.GenerateUniqueID())

	fsLog(fs, logger.LevelDebug, "moving existing target file %s ==> %s", targetIrodsPath, backupIrodsPath)
	if err := fs.irodsClient.RenameFileToFile(targetIrodsPath, backupIrodsPath); err != nil {
		return err
	}

	if err := fs.irodsClient.RenameFileToFile(sourceIrodsPath, targetIrodsPath); err != nil {
		if errRestore := fs.irodsClient.RenameFileToFile(backupIrodsPath, targetIrodsPath); errRestore != nil {
			fsLog(fs, logger.LevelError, "unable to restore backup file %s ==> %s: %v", backupIrodsPath, targetIrodsPath, errRestore)
		}
		return err
	}

	if err := fs.irodsClient.RemoveFile(backupIrodsPath, true); err != nil {
		fsLog(fs, logger.LevelWarn, "unable to remove backup file %s: %v", backupIrodsPath, err)
	}
	return nil
}

// Remove removes the named file or (empty) directory.
func (fs *IRODSFs) Remove(name string, isDir bool) error {
	if fs.irodsClient == nil {
		// not connected yet
		return fmt.Errorf("irods client is not connected yet")
	}

	irodsPath := fs.getIRODSPath(name)
	if isDir {
		fsLog(fs, logger.LevelDebug, "removing a dir %s", irodsPath)
		err := fs.irodsClient.RemoveDir(irodsPath, false, true)
		if err != nil {
			if irodstypes.IsCollectionNotEmptyError(err) {
				return fmt.Errorf("cannot remove non empty directory %q", irodsPath)
			}
			return err
		}
		return nil
	}
	fsLog(fs, logger.LevelDebug, "removing a file %s", irodsPath)
	return fs.irodsClient.RemoveFile(irodsPath, true)
}

// Mkdir creates a new directory with the specified name and default permissions
func (fs *IRODSFs) Mkdir(name string) error {
	if fs.irodsClient == nil {
		// not connected yet
		return fmt.Errorf("irods client is not connected yet")
	}

	irodsPath := fs.getIRODSPath(name)
	_, err := fs.irodsClient.Stat(irodsPath)
	if err == nil {
		return fmt.Errorf("cannot make directory %q: %w", irodsPath, os.ErrExist)
	}
	if !fs.IsNotExist(err) {
		return err
	}

	fsLog(fs, logger.LevelDebug, "making a dir %s", irodsPath)
	return fs.irodsClient.MakeDir(irodsPath, false)
}

// Symlink creates source as a symbolic link to target.
func (*IRODSFs) Symlink(source, target string) error {
	return ErrVfsUnsupported
}

// Readlink returns the destination of the named symbolic link
func (*IRODSFs) Readlink(name string) (string, error) {
	return "", ErrVfsUnsupported
}

// Chown changes the numeric uid and gid of the named file.
func (*IRODSFs) Chown(name string, uid int, gid int) error {
	return ErrVfsUnsupported
}

// Chmod changes the mode of the named file to mode.
func (*IRODSFs) Chmod(name string, mode os.FileMode) error {
	return ErrVfsUnsupported
}

// Chtimes changes the access and modification times of the named file.
func (fs *IRODSFs) Chtimes(name string, atime, mtime time.Time, isUploading bool) error {
	return ErrVfsUnsupported
}

// Truncate changes the size of the named file.
func (fs *IRODSFs) Truncate(name string, size int64) error {
	if fs.irodsClient == nil {
		// not connected yet
		return fmt.Errorf("irods client is not connected yet")
	}

	irodsPath := fs.getIRODSPath(name)

	fsLog(fs, logger.LevelDebug, "truncating a file %s to %d", irodsPath, size)
	return fs.irodsClient.TruncateFile(irodsPath, size)
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries.
func (fs *IRODSFs) ReadDir(dirname string) (DirLister, error) {
	if fs.irodsClient == nil {
		// not connected yet
		return nil, fmt.Errorf("irods client is not connected yet")
	}

	irodsPath := fs.getIRODSPath(dirname)

	var result []os.FileInfo

	entries, err := fs.irodsClient.List(irodsPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		fi := fs.makeFileInfoFromEntry(entry)
		result = append(result, fi)
	}
	return &baseDirLister{result}, nil
}

// IsUploadResumeSupported returns true if resuming uploads is supported.
// Resuming uploads is not supported on iRODS
func (*IRODSFs) IsUploadResumeSupported() bool {
	return false
}

// IsConditionalUploadResumeSupported returns if resuming uploads is supported
// for the specified size
// Resuming uploads is not supported on iRODS
func (*IRODSFs) IsConditionalUploadResumeSupported(size int64) bool {
	return false
}

// IsAtomicUploadSupported returns true if atomic upload is supported.
// iRODS uploads are already atomic, we don't need to upload to a temporary
// file
func (*IRODSFs) IsAtomicUploadSupported() bool {
	return false
}

// IsNotExist returns a boolean indicating whether the error is known to
// report that a file or directory does not exist
func (fs *IRODSFs) IsNotExist(err error) bool {
	if err == nil {
		return false
	}

	if irodstypes.IsFileNotFoundError(err) {
		return true
	}
	return false
}

// IsPermission returns a boolean indicating whether the error is known to
// report that permission is denied.
func (*IRODSFs) IsPermission(err error) bool {
	if err == nil {
		return false
	}

	// Go-iRODSClient does not report permission error at this point
	return false
}

// IsNotSupported returns true if the error indicate an unsupported operation
func (*IRODSFs) IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrVfsUnsupported
}

// CheckRootPath creates the specified local root directory if it does not exists
func (fs *IRODSFs) CheckRootPath(username string, uid int, gid int) bool {
	// we need a local directory for temporary files
	osFs := NewOsFs(fs.ConnectionID(), fs.localTempDir, "", nil)
	return osFs.CheckRootPath(username, uid, gid)
}

// ScanRootDirContents returns the number of files contained in the bucket,
// and their size
func (fs *IRODSFs) ScanRootDirContents() (int, int64, error) {
	return fs.GetDirSize("/")
}

// CheckMetadata checks the metadata consistency
func (fs *IRODSFs) CheckMetadata() error {
	return nil
}

// GetDirSize returns the number of files and the size for a folder
// including any subfolders
func (fs *IRODSFs) GetDirSize(dirname string) (int, int64, error) {
	if fs.irodsClient == nil {
		// not connected yet
		return 0, 0, fmt.Errorf("irods client is not connected yet")
	}

	irodsPath := fs.getIRODSPath(dirname)

	numFiles := 0
	size := int64(0)

	entry, err := fs.irodsClient.Stat(irodsPath)
	if err != nil {
		return 0, 0, err
	}

	if entry.Type == irodsfs.DirectoryEntry {
		err = fs.Walk(dirname, func(_ string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info != nil && info.Mode().IsRegular() {
				size += info.Size()
				numFiles++
			}
			return nil
		})
	}
	return numFiles, size, err
}

// GetAtomicUploadPath returns the path to use for an atomic upload.
func (*IRODSFs) GetAtomicUploadPath(name string) string {
	return ""
}

// GetRelativePath returns the path for a file relative to the user's home dir.
// This is the path as seen by SFTPGo users
func (fs *IRODSFs) GetRelativePath(name string) string {
	rel := path.Clean(name)
	if rel == "." {
		rel = ""
	}
	if !path.IsAbs(rel) {
		rel = "/" + rel
	}
	if fs.mountPath != "" {
		rel = path.Join(fs.mountPath, rel)
	}
	return rel
}

// Walk walks the file tree rooted at root, calling walkFn for each file or
// directory in the tree, including root. The result are unordered
func (fs *IRODSFs) Walk(root string, walkFn filepath.WalkFunc) error {
	if fs.irodsClient == nil {
		// not connected yet
		return fmt.Errorf("irods client is not connected yet")
	}

	info, err := fs.Stat(root)
	if err != nil {
		return walkFn(root, nil, err)
	}
	if err := walkFn(root, info, nil); err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}

	// the stack contains fs paths, they are converted to iRODS paths only to list them
	pathStack := []string{root}

	for len(pathStack) > 0 {
		// pop one
		dirName := pathStack[len(pathStack)-1]
		pathStack = pathStack[0 : len(pathStack)-1]

		entries, err := fs.irodsClient.List(fs.getIRODSPath(dirName))
		if err != nil {
			if err := walkFn(dirName, nil, err); err != nil {
				return err
			}
			continue
		}

		for _, entry := range entries {
			entryPath := path.Join(dirName, entry.Name)
			if err := walkFn(entryPath, fs.makeFileInfoFromEntry(entry), nil); err != nil {
				return err
			}

			if entry.Type == irodsfs.DirectoryEntry {
				// add to stack
				pathStack = append(pathStack, entryPath)
			}
		}
	}
	return nil
}

// Join joins any number of path elements into a single path
func (*IRODSFs) Join(elem ...string) string {
	return path.Join(elem...)
}

// HasVirtualFolders returns true if folders are emulated
func (*IRODSFs) HasVirtualFolders() bool {
	return false
}

// ResolvePath returns the matching filesystem path for the specified virtual path
func (fs *IRODSFs) ResolvePath(virtualPath string) (string, error) {
	if fs.mountPath != "" {
		if after, found := strings.CutPrefix(virtualPath, fs.mountPath); found {
			virtualPath = after
		}
	}
	virtualPath = path.Clean("/" + virtualPath)
	return virtualPath, nil
}

// GetMimeType returns the content type
func (fs *IRODSFs) GetMimeType(name string) (string, error) {
	if fs.irodsClient == nil {
		// not connected yet
		return "", fmt.Errorf("irods client is not connected yet")
	}

	irodsPath := fs.getIRODSPath(name)
	irodsFileHandle, err := fs.irodsClient.OpenFile(irodsPath, "", string(irodstypes.FileOpenModeReadOnly))
	if err != nil {
		return "", err
	}
	defer irodsFileHandle.Close()

	buffer := make([]byte, 512)
	readLen, err := irodsFileHandle.Read(buffer)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", err
	}

	ctype := http.DetectContentType(buffer[:readLen])
	// Rewind file.
	_, err = irodsFileHandle.Seek(0, io.SeekStart)
	return ctype, err
}

// Close closes the fs
func (fs *IRODSFs) Close() error {
	if fs.irodsClient != nil {
		fs.irodsClient.Release()
		fs.irodsClient = nil
	}
	return nil
}

// GetAvailableDiskSize return the available size for the specified path
func (fs *IRODSFs) GetAvailableDiskSize(dirName string) (*sftp.StatVFS, error) {
	return nil, ErrStorageSizeUnavailable
}

func (fs *IRODSFs) setConfigDefaults() {
	// nothing to set
}

func (fs *IRODSFs) createConnection() error {
	host, port, err := fs.config.getHostPort()
	if err != nil {
		return err
	}

	zone, err := fs.config.getZone()
	if err != nil {
		return err
	}

	// fix if proxy username is not given correctly
	if fs.config.ProxyUsername == "" {
		fs.config.ProxyUsername = fs.config.Username
	}

	var irodsAccount *irodstypes.IRODSAccount

	switch strings.ToLower(fs.config.AuthScheme) {
	case "", "native":
		irodsAccount, err = irodstypes.CreateIRODSProxyAccount(host, port, fs.config.Username, zone, fs.config.ProxyUsername, zone, irodstypes.AuthSchemeNative, fs.config.Password.GetPayload(), fs.config.ResourceServer)
		if err != nil {
			return err
		}
	case "pam":
		irodsAccount, err = irodstypes.CreateIRODSProxyAccount(host, port, fs.config.Username, zone, fs.config.ProxyUsername, zone, irodstypes.AuthSchemePAM, fs.config.Password.GetPayload(), fs.config.ResourceServer)
		if err != nil {
			return err
		}
	case "pam_password":
		irodsAccount, err = irodstypes.CreateIRODSProxyAccount(host, port, fs.config.Username, zone, fs.config.ProxyUsername, zone, irodstypes.AuthSchemePAMPassword, fs.config.Password.GetPayload(), fs.config.ResourceServer)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown authentication scheme %s", fs.config.AuthScheme)
	}

	if fs.config.RequireClientServerNegotiation {
		require := irodstypes.GetCSNegotiationPolicyRequest(fs.config.ClientServerNegotiationPolicy)
		irodsAccount.SetCSNegotiation(true, require)

		if fs.config.isSSLPossible() {
			// SSL
			sslConf := irodstypes.IRODSSSLConfig{
				CACertificatePath:       fs.config.SSLCACertificatePath,
				EncryptionKeySize:       fs.config.SSLKeySize,
				EncryptionAlgorithm:     fs.config.SSLAlgorithm,
				EncryptionSaltSize:      fs.config.SSLSaltSize,
				EncryptionNumHashRounds: fs.config.SSLHashRounds,
				VerifyServer:            irodstypes.SSLVerifyServerNone,
			}

			irodsAccount.SetSSLConfiguration(&sslConf)
		}
	}

	fsLog(fs, logger.LevelDebug, "connecting to iRODS %s:%d using %s auth", irodsAccount.Host, irodsAccount.Port, irodsAccount.AuthenticationScheme)

	irodsClient, err := irodsfs.NewFileSystemWithDefault(irodsAccount, "sftpgo")
	if err != nil {
		return err
	}

	fs.irodsClient = irodsClient
	return nil
}

// makeFileInfoFromEntry creates file info from an iRODS Entry
func (fs *IRODSFs) makeFileInfoFromEntry(entry *irodsfs.Entry) *FileInfo {
	isDir := entry.Type == irodsfs.DirectoryEntry
	return NewFileInfo(entry.Name, isDir, entry.Size, entry.ModifyTime, true)
}

// convert sftpgo path to irods path
func (fs *IRODSFs) getIRODSPath(virtualPath string) string {
	if len(virtualPath) == 0 {
		return ""
	}

	return path.Join(fs.config.CollectionPath, strings.TrimPrefix(virtualPath, "/"))
}
