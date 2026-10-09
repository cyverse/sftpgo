package vfs

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	irodsFsName          = "irodsfs"
	defaultIRODSPort int = 1247
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

func (c *IRODSFsConfig) setNilSecretsIfEmpty() {
	if c.Password != nil && c.Password.IsEmpty() {
		c.Password = nil
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
	if c.PoolEndpoint != other.PoolEndpoint {
		return false
	}
	c.setEmptyCredentialsIfNil()
	other.setEmptyCredentialsIfNil()
	return c.Password.IsEqual(other.Password)
}

func (c *IRODSFsConfig) setEmptyCredentialsIfNil() {
	if c.Password == nil {
		c.Password = kms.NewEmptySecret()
	}
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
		return util.NewI18nError(errors.New("endpoint cannot be empty"), util.I18nErrorEndpointRequired)
	}
	if _, _, err := c.getHostPort(); err != nil {
		return util.NewI18nError(fmt.Errorf("invalid endpoint: %v", err), util.I18nErrorEndpointInvalid)
	}
	if c.CollectionPath == "" {
		return errors.New("collection path cannot be empty")
	}
	if _, err := c.getZone(); err != nil {
		return err
	}
	if c.Username == "" {
		return util.NewI18nError(errors.New("username cannot be empty"), util.I18nErrorFsUsernameRequired)
	}
	scheme := strings.ToLower(c.AuthScheme)
	switch scheme {
	case "", "native", "pam", "pam_password":
	default:
		return errors.New("unknown authentication scheme")
	}

	requireSSL := c.isSSLPossible()
	if (scheme == "pam" || scheme == "pam_password") && !requireSSL {
		return errors.New("PAM authentication requires client-server negotiation with CS_NEG_REQUIRE or CS_NEG_DONT_CARE policy")
	}

	if requireSSL {
		if c.SSLCACertificatePath == "" {
			return errors.New("SSL CA certificate path cannot be empty when SSL is used")
		}
		if c.SSLKeySize == 0 {
			return errors.New("SSL encryption key size cannot be 0 when SSL is used")
		}
		if c.SSLAlgorithm == "" {
			return errors.New("SSL encryption algorithm cannot be empty when SSL is used")
		}
		if c.SSLSaltSize == 0 {
			return errors.New("SSL encryption salt size cannot be 0 when SSL is used")
		}
		if c.SSLHashRounds == 0 {
			return errors.New("SSL encryption hash rounds cannot be 0 when SSL is used")
		}
	}

	if c.PoolEndpoint != "" {
		if err := c.validatePoolEndpoint(); err != nil {
			return err
		}
	}

	if err := c.validateCredentials(); err != nil {
		return err
	}
	return nil
}

// isSSLPossible returns true if the client-server negotiation can result in an SSL connection.
// The policy is parsed the same way go-irodsclient does when connecting, this file must not
// import go-irodsclient so that it can be built with the noirods tag
func (c *IRODSFsConfig) isSSLPossible() bool {
	if !c.RequireClientServerNegotiation {
		return false
	}
	switch strings.TrimSpace(strings.ToUpper(c.ClientServerNegotiationPolicy)) {
	case "CS_NEG_REQUIRE", "SSL", "CS_NEG_DONT_CARE", "DONT_CARE", "":
		return true
	default:
		// CS_NEG_REFUSE, TCP and unknown values result in a plain TCP connection
		return false
	}
}

// validatePoolEndpoint checks the irodsfs-pool service endpoint. Supported formats are
// "tcp://host:port", "unix:///path/to/socket" and "host:port"
func (c *IRODSFsConfig) validatePoolEndpoint() error {
	address := c.PoolEndpoint
	if scheme, rest, found := strings.Cut(c.PoolEndpoint, "://"); found {
		switch strings.ToLower(scheme) {
		case "unix":
			if !strings.HasPrefix(rest, "/") || len(rest) < 2 {
				return fmt.Errorf("invalid pool endpoint %q, the unix socket path must be absolute", c.PoolEndpoint)
			}
			return nil
		case "tcp":
			address = rest
		default:
			return fmt.Errorf("invalid pool endpoint %q, unsupported scheme %q", c.PoolEndpoint, scheme)
		}
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return fmt.Errorf("invalid pool endpoint %q, host:port expected", c.PoolEndpoint)
	}
	if port, err := strconv.Atoi(portStr); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %q in the pool endpoint %q", portStr, c.PoolEndpoint)
	}
	return nil
}

func (c *IRODSFsConfig) validateCredentials() error {
	if c.Password.IsEmpty() {
		return util.NewI18nError(errors.New("credentials cannot be empty"), util.I18nErrorFsCredentialsRequired)
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
		var errI18n *util.I18nError
		errValidation := util.NewValidationError(fmt.Sprintf("could not validate IRODS fs config: %v", err))
		if errors.As(err, &errI18n) {
			return util.NewI18nError(errValidation, errI18n.Message)
		}
		return util.NewI18nError(errValidation, util.I18nErrorFsValidation)
	}
	if c.Password.IsPlain() {
		c.Password.SetAdditionalData(additionalData)
		if err := c.Password.Encrypt(); err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("could not encrypt IRODS fs password: %v", err)),
				util.I18nErrorFsValidation,
			)
		}
	}
	return nil
}

// getZone extracts zone from CollectionPath (the first subdirectory part in the path)
// if it cannot extract, returns empty string with an error
func (c *IRODSFsConfig) getZone() (string, error) {
	if !strings.HasPrefix(c.CollectionPath, "/") {
		return "", fmt.Errorf("cannot extract zone from path %q, the path must be absolute", c.CollectionPath)
	}

	zone, _, _ := strings.Cut(c.CollectionPath[1:], "/")
	if zone == "" {
		return "", fmt.Errorf("cannot extract zone from path %q", c.CollectionPath)
	}
	return zone, nil
}

// getHostPort parses the endpoint as host, host:port, IPv6 address or [IPv6 address]:port.
// If the port is not specified, the default iRODS port is used
func (c *IRODSFsConfig) getHostPort() (string, int, error) {
	host, portStr, err := net.SplitHostPort(c.Endpoint)
	if err != nil {
		// no port, the endpoint can be a host name or an IPv4/IPv6 address
		host = c.Endpoint
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		if strings.ContainsAny(host, "[]") || (strings.Contains(host, ":") && net.ParseIP(host) == nil) {
			return "", 0, fmt.Errorf("cannot parse host and port from the endpoint %q", c.Endpoint)
		}
		portStr = ""
	}
	if host == "" {
		return "", 0, fmt.Errorf("cannot parse host from the endpoint %q", c.Endpoint)
	}
	if portStr == "" && err == nil {
		return "", 0, fmt.Errorf("cannot parse port from the endpoint %q", c.Endpoint)
	}

	port := defaultIRODSPort
	if portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port %q in the endpoint %q", portStr, c.Endpoint)
		}
	}
	return host, port, nil
}
