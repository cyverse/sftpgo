//go:build noirods
// +build noirods

package vfs

import (
	"errors"

	"github.com/drakkan/sftpgo/v2/version"
)

func init() {
	version.AddFeature("-irods")
}

// NewIRODSFs returns an error, IRODS is disabled
func NewIRODSFs(connectionID, localTempDir, mountPath string, config IRODSFsConfig) (Fs, error) {
	return nil, errors.New("IRODS disabled at build time")
}
