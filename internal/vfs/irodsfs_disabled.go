//go:build noirods
// +build noirods

package vfs

import (
	"errors"

	"github.com/drakkan/sftpgo/v2/internal/version"
)

func init() {
	version.AddFeature("-irods")
}

// NewIRODSFs returns an error, IRODS is disabled
func NewIRODSFs(_, _, _ string, _ IRODSFsConfig) (Fs, error) {
	return nil, errors.New("IRODS disabled at build time")
}
