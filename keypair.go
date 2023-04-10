package keypair

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"gopkg.in/square/go-jose.v2/jwt"
)

var serviceAccountToken = os.Getenv("KEYPAIR_SERVICE_ACCOUNT_TOKEN")

func init() {
	caddy.RegisterModule(KeypairMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("keypair", parseCaddyfile)
}

type KeypairMiddleware struct {
	w      io.Writer
	logger *zap.Logger
}

func (KeypairMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.keypair",
		New: func() caddy.Module { return new(KeypairMiddleware) },
	}
}

func (m *KeypairMiddleware) Provision(ctx caddy.Context) error {
	m.w = os.Stdout
	m.logger = caddy.Log()
	return nil
}

// Validate implements caddy.Validator.
func (m *KeypairMiddleware) Validate() error {
	if m.w == nil {
		return fmt.Errorf("no writer")
	}
	return nil
}

type Claims struct {
	PublicKey string `json:"pub"`
	Expiry    int    `json:"exp"`
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m KeypairMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	authHeader := r.Header.Get("Authorization")

	raw := strings.TrimPrefix(authHeader, "Bearer ")
	if raw == "" {
		return fmt.Errorf("no bearer token found")
	}

	claims, err := validateRequest(raw)
	if err != nil {
		return err
	}

	m.logger.Info("Headers before:", zap.String("headers", fmt.Sprintf("%+v", r.Header)))
	r.Header.Set("Authorization", "Bearer "+serviceAccountToken)
	// r.Header.Set("Impersonate-User", userName)
	m.logger.Info("Headers:", zap.String("headers", fmt.Sprintf("%+v", r.Header)))
	return next.ServeHTTP(w, r)
}

func validateRequest(raw string) (*Claims, error) {
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT signature: %w", err)
	}

	claims := Claims{}
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("invalid token claims: %w", err)
	}

	// Validate claims with provided public key
	// publicKey, err := parsePublicKey(claims.PublicKey)
	// if err != nil {
	// 	return nil, fmt.Errorf("invalid public key: %w", err)
	// }

	// if err := tok.Claims(publicKey, &claims); err != nil {
	// 	return nil, fmt.Errorf("JWT signature does not match provided public key: %w", err)
	// }

	return &claims, nil
}

func parsePublicKey(publicKey string) (interface{}, error) {
	// Remove the key type prefix
	keyData := publicKey[len("ssh-rsa "):]
	// Decode the base64-encoded key data
	keyBytes, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64: %v", err)
	}
	// Parse the SSH public key
	parsedKey, err := ssh.ParsePublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}
	return parsedKey, nil
}

func (m *KeypairMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m KeypairMiddleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*KeypairMiddleware)(nil)
	_ caddy.Validator             = (*KeypairMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*KeypairMiddleware)(nil)
	_ caddyfile.Unmarshaler       = (*KeypairMiddleware)(nil)
)
