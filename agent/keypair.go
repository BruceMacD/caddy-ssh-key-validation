package keypair

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"gopkg.in/square/go-jose.v2/jwt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var serviceAccountToken = os.Getenv("KEYPAIR_SERVICE_ACCOUNT_TOKEN") // TODO: get this from the secret directly rather than the environment vars

func init() {
	caddy.RegisterModule(KeypairMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("keypair", parseCaddyfile)
}

type KeypairMiddleware struct {
	w           io.Writer
	logger      *zap.Logger
	userMapping map[string]string
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

	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	namespace := "default"
	name := "keypair-user-mapping"
	userKeys, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	userMapping := make(map[string]string)

	for uname, pubKey := range userKeys.Data {
		userMapping[pubKey] = uname
	}

	m.userMapping = userMapping

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
	m.logger.Info("waddup")
	authHeader := r.Header.Get("Authorization")

	raw := strings.TrimPrefix(authHeader, "Bearer ")
	if raw == "" {
		return fmt.Errorf("no bearer token")
	}

	claims, err := validateRequest(raw)
	if err != nil {
		return err
	}

	user := m.userMapping[claims.PublicKey]
	if user == "" {
		return fmt.Errorf("unauthorized")
	}
	r.Header.Set("Authorization", "Bearer "+serviceAccountToken)
	r.Header.Set("Impersonate-User", user)

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
	publicKey, err := parsePublicKey(claims.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	if err := tok.Claims(publicKey, &claims); err != nil {
		return nil, fmt.Errorf("JWT signature does not match provided public key: %w", err)
	}

	exp := time.Unix(int64(claims.Expiry), 0)
	if time.Now().After(exp) {
		return nil, fmt.Errorf("token is expired")
	}

	return &claims, nil
}

func parsePublicKey(publicKey string) (interface{}, error) {
	sshPublicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		return nil, err
	}

	cryptoPublicKey := sshPublicKey.(ssh.CryptoPublicKey)

	switch publicKey := cryptoPublicKey.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		publicKey, ok := cryptoPublicKey.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("failed to parse invalid RSA key")
		}
		return publicKey, nil
	case *ecdsa.PublicKey:
		publicKey, ok := cryptoPublicKey.CryptoPublicKey().(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("failed to parse invalid ECDSA key")
		}
		return publicKey, nil
	}

	return nil, fmt.Errorf("unsupported public key type")
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
