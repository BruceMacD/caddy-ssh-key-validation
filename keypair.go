package keypair

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

var (
	serviceAccountToken = ""
	serviceAccountName  = ""
)

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
	Nonce     string `json:"nonce"`
	Expiry    int    `json:"exp"`
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m KeypairMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// authHeader := r.Header.Get("Authorization")

	// raw := strings.TrimPrefix(authHeader, "Bearer ")
	// if raw == "" {
	// 	return fmt.Errorf("no bearer token found")
	// }

	// m.w.Write([]byte(authHeader))

	// tok, err := jwt.ParseSigned(raw)
	// if err != nil {
	// 	return fmt.Errorf("invalid JWT signature: %w", err)
	// }

	// claims := Claims{}
	// if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
	// 	return fmt.Errorf("invalid token claims: %w", err)
	// }

	// TODO: validate claims with provided public key

	// err = allClaims.Claims.Validate(jwt.Expected{Time: time.Now().UTC()})
	// switch {
	// case errors.Is(err, jwt.ErrExpired):
	// 	return c, err
	// case err != nil:
	// 	return c, fmt.Errorf("invalid JWT %w", err)
	// }

	// if allClaims.Custom.Name == "" {
	// 	return c, fmt.Errorf("no username in JWT claims")
	// }

	m.logger.Info("called middleware")
	r.Header.Set("Authorization", "Bearer "+serviceAccountToken)
	r.Header.Set("Impersonate-User", serviceAccountName)
	return next.ServeHTTP(w, r)
}

func (m *KeypairMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// TODO: can reads args here
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
