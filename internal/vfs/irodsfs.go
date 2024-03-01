//go:build !noirods
// +build !noirods

package vfs

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/eikenb/pipeat"
	"github.com/pkg/sftp"
	"github.com/sftpgo/sdk"

	irodsfs "github.com/cyverse/go-irodsclient/fs"
	irodstypes "github.com/cyverse/go-irodsclient/irods/types"
)

const (
	defaultIRODSPort int = 1247
	irodsReadSize    int = 128 * 1024      // 128KB
	irodsWriteSize   int = 8 * 1024 * 1024 // 8MB
)

// IRODSFsConfig defines the configuration for iRODS Storage
type IRODSFsConfig struct {
	sdk.BaseIRODSFsConfig
	Password *kms.Secret `json:"password,omitempty"`
}

// HideConfidentialData hides confidential data
func (c *IRODSFsConfig) HideConfidentialData() {
	if c.Password != nil {
		c.Password.Hide()
	}
}

func (c *IRODSFsConfig) setEmptyCredentialsIfNil() {
	if c.Password == nil {
		c.Password = kms.NewEmptySecret()
	}
}

func (c *IRODSFsConfig) isEqual(other *IRODSFsConfig) bool {
	if c.Endpoint != other.Endpoint {
		return false
	}
	if c.CollectionPath != other.CollectionPath {
		return false
	}
	if c.Username != other.Username {
		return false
	}
	if c.ProxyUsername != other.ProxyUsername {
		return false
	}
	if c.ResourceServer != other.ResourceServer {
		return false
	}
	if c.AuthScheme != other.AuthScheme {
		return false
	}
	if c.RequireClientServerNegotiation != other.RequireClientServerNegotiation {
		return false
	}
	if c.ClientServerNegotiationPolicy != other.ClientServerNegotiationPolicy {
		return false
	}
	if c.SSLCACertificatePath != other.SSLCACertificatePath {
		return false
	}
	if c.SSLKeySize != other.SSLKeySize {
		return false
	}
	if c.SSLAlgorithm != other.SSLAlgorithm {
		return false
	}
	if c.SSLSaltSize != other.SSLSaltSize {
		return false
	}
	if c.SSLHashRounds != other.SSLHashRounds {
		return false
	}
	c.setEmptyCredentialsIfNil()
	other.setEmptyCredentialsIfNil()
	return c.Password.IsEqual(other.Password)
}

func (c *IRODSFsConfig) isSameResource(other IRODSFsConfig) bool {
	if c.Endpoint != other.Endpoint {
		return false
	}
	if c.CollectionPath != other.CollectionPath {
		return false
	}
	if c.ResourceServer != other.ResourceServer {
		return false
	}
	return true
}

// validate returns an error if the configuration is not valid
func (c *IRODSFsConfig) validate() error {
	c.setEmptyCredentialsIfNil()
	if c.Endpoint == "" {
		return errors.New("endpoint cannot be empty")
	}
	if _, _, err := c.getHostPort(); err != nil {
		return err
	}
	if c.CollectionPath == "" {
		return errors.New("collection path cannot be empty")
	}
	if _, err := c.getZone(); err != nil {
		return err
	}
	if c.Username == "" {
		return errors.New("username cannot be empty")
	}
	if strings.ToLower(c.AuthScheme) != "" && strings.ToLower(c.AuthScheme) != "native" && strings.ToLower(c.AuthScheme) != "pam" {
		return errors.New("unknown authentication scheme")
	}

	requireSSL := false
	if strings.ToLower(c.AuthScheme) == "pam" {
		requireSSL = true
	}
	if c.RequireClientServerNegotiation {
		if strings.ToLower(c.ClientServerNegotiationPolicy) == "cs_neg_require" {
			requireSSL = true
		} else if strings.ToLower(c.ClientServerNegotiationPolicy) == "cs_neg_dont_care" {
			requireSSL = true
		}
	}

	if requireSSL {
		if c.SSLCACertificatePath == "" {
			return errors.New("SSL CA certificate path cannot be empty when PAM authentication is used")
		}
		if c.SSLKeySize == 0 {
			return errors.New("SSL encryption key size cannot be 0 when PAM authentication is used")
		}
		if c.SSLAlgorithm == "" {
			return errors.New("SSL encryption algorithm cannot be 0 when PAM authentication is used")
		}
		if c.SSLSaltSize == 0 {
			return errors.New("SSL encryption salt size cannot be 0 when PAM authentication is used")
		}
		if c.SSLHashRounds == 0 {
			return errors.New("SSL encryption has rounds cannot be 0 when PAM authentication is used")
		}
	}

	if err := c.validateCredentials(); err != nil {
		return err
	}
	return nil
}

func (c *IRODSFsConfig) validateCredentials() error {
	if c.Password.IsEmpty() {
		return errors.New("credentials cannot be empty")
	}
	if c.Password.IsEncrypted() && !c.Password.IsValid() {
		return errors.New("invalid encrypted password")
	}
	if !c.Password.IsEmpty() && !c.Password.IsValidInput() {
		return errors.New("invalid password")
	}
	return nil
}

// ValidateAndEncryptCredentials validates the config and encrypts credentials if they are in plain text
func (c *IRODSFsConfig) ValidateAndEncryptCredentials(additionalData string) error {
	if err := c.validate(); err != nil {
		return util.NewValidationError(fmt.Sprintf("could not validate IRODS fs config: %v", err))
	}
	if c.Password.IsPlain() {
		c.Password.SetAdditionalData(additionalData)
		if err := c.Password.Encrypt(); err != nil {
			return util.NewValidationError(fmt.Sprintf("could not encrypt IRODS fs password: %v", err))
		}
	}
	return nil
}

// getZone extracts zone from CollectionPath (the first subdirectory part in the path)
// if it cannot extract, returns empty string with an error
func (c *IRODSFsConfig) getZone() (string, error) {
	if len(c.CollectionPath) < 1 {
		return "", fmt.Errorf("cannot extract zone from path")
	}

	if c.CollectionPath[0] != '/' {
		return "", fmt.Errorf("cannot extract zone from path")
	}

	parts := strings.Split(c.CollectionPath[1:], "/")
	if len(parts) >= 1 {
		return parts[0], nil
	}
	return "", fmt.Errorf("cannot extract zone from path")
}

func (c *IRODSFsConfig) getHostPort() (string, int, error) {
	parts := strings.Split(c.Endpoint, ":")
	if len(parts) == 2 {
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", 0, err
		}

		return parts[0], port, nil
	} else if len(parts) == 1 {
		// returns d
		return parts[0], defaultIRODSPort, nil
	}

	return "", 0, fmt.Errorf("cannot parse host and port from the endpoint '%s'", c.Endpoint)
}

// IRODSFs is a Fs implementation for iRODS Storage
type IRODSFs struct {
	connectionID string
	localTempDir string
	// if not empty this fs is mouted as virtual folder in the specified path
	mountPath   string
	config      *IRODSFsConfig
	irodsClient *irodsfs.FileSystem
}

func init() {
	version.AddFeature("+irods")
}

// NewIRODSFs returns an IRODSFs object that allows to interact with an iRODS
func NewIRODSFs(connectionID, localTempDir, mountPath string, irodsConfig IRODSFsConfig) (Fs, error) {
	if localTempDir == "" {
		if tempPath != "" {
			localTempDir = tempPath
		} else {
			localTempDir = filepath.Clean(os.TempDir())
		}
	}
	fs := &IRODSFs{
		connectionID: connectionID,
		localTempDir: localTempDir,
		mountPath:    getMountPath(mountPath),
		config:       &irodsConfig,
	}

	fsLog(fs, logger.LevelDebug, "creating a new iRODS Fs connID: %s, localTempDir: %s, mountPath: %s\n    iRODS Host: %s, Auth: %s, Collection Path: %s", fs.connectionID, fs.localTempDir, fs.mountPath, fs.config.Endpoint, fs.config.AuthScheme, fs.config.CollectionPath)

	if err := fs.config.validate(); err != nil {
		return fs, err
	}
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
	return fmt.Sprintf("iRODS Storage %#v", fs.config.Endpoint)
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
func (fs *IRODSFs) Open(name string, offset int64) (File, *pipeat.PipeReaderAt, func(), error) {
	if fs.irodsClient == nil {
		// not connected yet
		return nil, nil, nil, fmt.Errorf("irods client is not connected yet")
	}

	irodsPath := fs.getIRODSPath(name)
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}

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

	go func() {
		n, err := fs.copy(w, irodsFileHandle, irodsReadSize)
		w.CloseWithError(err) //nolint:errcheck
		irodsFileHandle.Close()
		fsLog(fs, logger.LevelDebug, "download completed, path: %#v size: %v, err: %v", irodsPath, n, err)
	}()

	return nil, r, nil, nil
}

// Create creates or opens the named file for writing
func (fs *IRODSFs) Create(name string, flag, _ int) (File, *PipeWriter, func(), error) {
	if fs.irodsClient == nil {
		// not connected yet
		return nil, nil, nil, fmt.Errorf("irods client is not connected yet")
	}

	irodsPath := fs.getIRODSPath(name)
	r, w, err := pipeat.PipeInDir(fs.localTempDir)
	if err != nil {
		return nil, nil, nil, err
	}
	p := NewPipeWriter(w)

	var irodsFileHandle *irodsfs.FileHandle
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

	go func() {
		bw := bufio.NewWriterSize(irodsFileHandle, irodsWriteSize)
		// we don't use io.Copy since bufio.Writer implements io.WriterTo and
		// so it calls the sftp.File WriteTo method without buffering
		n, err := fs.copy(bw, r, irodsReadSize)
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
		fsLog(fs, logger.LevelDebug, "upload completed, path: %#v, readed bytes: %v, err: %v", irodsPath, n, err)
	}()

	return nil, p, nil, nil
}

// Rename renames (moves) source to target.
func (fs *IRODSFs) Rename(source, target string) error {
	if fs.irodsClient == nil {
		// not connected yet
		return fmt.Errorf("irods client is not connected yet")
	}

	if source == target {
		return nil
	}

	sourceIrodsPath := fs.getIRODSPath(source)
	targetIrodsPath := fs.getIRODSPath(target)

	fsLog(fs, logger.LevelDebug, "renaming a file %s ==> %s", sourceIrodsPath, targetIrodsPath)

	entry, err := fs.irodsClient.Stat(sourceIrodsPath)
	if err != nil {
		return err
	}

	if entry.Type == irodsfs.DirectoryEntry {
		return fs.irodsClient.RenameDirToDir(sourceIrodsPath, targetIrodsPath)
	}
	return fs.irodsClient.RenameFileToFile(sourceIrodsPath, targetIrodsPath)
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
				return fmt.Errorf("cannot remove non empty directory: %#v", irodsPath)
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
	if !fs.irodsClient.ExistsDir(irodsPath) {
		fsLog(fs, logger.LevelDebug, "making a dir %s", irodsPath)
		fs.irodsClient.MakeDir(irodsPath, false)
		return nil
	}
	return fmt.Errorf("cannot make directory that already exists: %#v", irodsPath)
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
// Truncate by path is not supported, while truncating an opened
// file is handled inside base transfer
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
func (fs *IRODSFs) ReadDir(dirname string) ([]os.FileInfo, error) {
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
	return result, nil
}

// IsUploadResumeSupported returns true if resuming uploads is supported.
// Resuming uploads is not supported on iRODS
func (*IRODSFs) IsUploadResumeSupported() bool {
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
	osFs := NewOsFs(fs.ConnectionID(), fs.localTempDir, "")
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
		err = fs.Walk(irodsPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info != nil && info.Mode().IsRegular() {
				size += info.Size()
				numFiles++
			}
			return err
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

	pathStack := []string{root}

	for len(pathStack) > 0 {
		// pop one
		dirName := pathStack[len(pathStack)-1]
		pathStack = pathStack[0 : len(pathStack)-1]

		irodsPath := fs.getIRODSPath(dirName)
		entries, err := fs.irodsClient.List(irodsPath)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			fi := fs.makeFileInfoFromEntry(entry)
			err = walkFn(entry.Path, fi, err)
			if err != nil {
				return err
			}

			if entry.Type == irodsfs.DirectoryEntry {
				// add to stack
				pathStack = append(pathStack, entry.Path)
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
		virtualPath = strings.TrimPrefix(virtualPath, fs.mountPath)
	}
	if !path.IsAbs(virtualPath) {
		virtualPath = path.Clean("/" + virtualPath)
	}

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
	default:
		return fmt.Errorf("unknown authentication scheme %s", fs.config.AuthScheme)
	}

	if fs.config.RequireClientServerNegotiation {
		require, err := irodstypes.GetCSNegotiationRequire(fs.config.ClientServerNegotiationPolicy)
		if err != nil {
			return fmt.Errorf("failed to create iRODS client-server negotiation policy from string '%s'", fs.config.ClientServerNegotiationPolicy)
		}

		irodsAccount.SetCSNegotiation(true, require)

		if len(fs.config.SSLCACertificatePath) > 0 {
			sslConf, err := irodstypes.CreateIRODSSSLConfig(fs.config.SSLCACertificatePath, fs.config.SSLKeySize, fs.config.SSLAlgorithm, fs.config.SSLSaltSize, fs.config.SSLHashRounds)
			if err != nil {
				return err
			}

			irodsAccount.SetSSLConfiguration(sslConf)
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
	mode := os.FileMode(0644)
	if entry.Type == irodsfs.DirectoryEntry {
		mode = os.FileMode(0755) | os.ModeDir
	}

	return &FileInfo{
		name:        entry.Name,
		sizeInBytes: entry.Size,
		modTime:     entry.ModifyTime,
		mode:        mode,
	}
}

// copy copies data from src to dst
func (fs *IRODSFs) copy(dst io.Writer, src io.Reader, buffersize int) (written int64, err error) {
	buf := make([]byte, buffersize)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write")
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

// convert sftpgo path to irods path
func (fs *IRODSFs) getIRODSPath(virtualPath string) string {
	if len(virtualPath) == 0 {
		return ""
	}

	return path.Join(fs.config.CollectionPath, strings.TrimPrefix(virtualPath, "/"))
}
