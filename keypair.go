package keypair

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
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

	// Read the certificate file
	certPath := "/data/caddy/certificates/local/localhost/localhost.crt"
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return err
	}

	// Check if the file is a valid PEM-encoded certificate
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid PEM-encoded certificate")
	}

	// Encode the certificate to base64 for use in a kube config file
	base64Cert := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(block))

	// Output the certificate in the expected format
	m.logger.Info("certificate authority", zap.String("certificate", base64Cert))

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
	// m.logger.Info("request headers:", zap.String("headers", fmt.Sprintf("%+v", r.Header)))
	authHeader := r.Header.Get("Authorization")

	raw := strings.TrimPrefix(authHeader, "Bearer ")
	if raw != "" {
		claims, err := validateRequest(raw)
		if err != nil {
			return err
		}

		user := m.userMapping[claims.PublicKey]
		if user == "" {
			return fmt.Errorf("unauthorized")
		}
		r.Header.Set("Authorization", "Bearer "+serviceAccountToken)
		r.Header.Set("Impersonate-User", "brucemacd")
	} else {
		m.logger.Info("non-bearer auth header", zap.String("auth header", authHeader))
	}

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

	// TODO: check expiry

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
