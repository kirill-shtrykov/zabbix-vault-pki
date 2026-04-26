package monitor_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/kirill-shtrykov/zabbix-vault-pki/internal/monitor"
)

const (
	rsaKeyBits          = 2048
	revokedDiscoverJSON = `{"data":[{"{#SN}":"valid-serial","{#CN}":"valid-cn"},` +
		`{"{#SN}":"revoked-serial","{#CN}":"revoked-cn"}]}`
)

func TestCertificateIsValid(t *testing.T) {
	t.Parallel()

	for _, tt := range certificateValidityCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.cert.IsValid(tt.revoked); got != tt.want {
				t.Fatalf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMonitorDiscoverAndExpiry(t *testing.T) {
	t.Parallel()

	validPEM, validCert := mustCertificatePEM(t, "valid-cn", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	revokedPEM, _ := mustCertificatePEM(t, "revoked-cn", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	server := httptest.NewServer(testVaultHandler(t, validPEM, revokedPEM))
	defer server.Close()

	client := mustAPIClient(t, server.URL)
	service := monitor.New(client)

	assertDiscover(t, service, false, `{"data":[{"{#SN}":"valid-serial","{#CN}":"valid-cn"}]}`)
	assertDiscover(t, service, true, revokedDiscoverJSON)

	expiry, err := service.Expiry("valid-serial")
	if err != nil {
		t.Fatalf("Expiry() error = %v", err)
	}

	if got, want := expiry, validCert.NotAfter.Unix(); got != want {
		t.Fatalf("Expiry() = %d, want %d", got, want)
	}
}

type certificateValidityCase struct {
	name    string
	cert    monitor.Certificate
	revoked bool
	want    bool
}

func certificateValidityCases() []certificateValidityCase {
	now := time.Now()

	return []certificateValidityCase{
		{
			name: "valid active certificate",
			cert: monitor.Certificate{
				Cert: &x509.Certificate{
					NotBefore: now.Add(-time.Hour),
					NotAfter:  now.Add(time.Hour),
				},
			},
			want: true,
		},
		{
			name: "expired certificate",
			cert: monitor.Certificate{
				Cert: &x509.Certificate{
					NotBefore: now.Add(-2 * time.Hour),
					NotAfter:  now.Add(-time.Hour),
				},
			},
			want: false,
		},
		{
			name: "revoked certificate excluded by default",
			cert: monitor.Certificate{
				Cert: &x509.Certificate{
					NotBefore: now.Add(-time.Hour),
					NotAfter:  now.Add(time.Hour),
				},
				Revocation: now.Add(-time.Minute),
			},
			want: false,
		},
		{
			name: "revoked certificate included when requested",
			cert: monitor.Certificate{
				Cert: &x509.Certificate{
					NotBefore: now.Add(-time.Hour),
					NotAfter:  now.Add(time.Hour),
				},
				Revocation: now.Add(-time.Minute),
			},
			revoked: true,
			want:    true,
		},
	}
}

func testVaultHandler(t *testing.T, validPEM, revokedPEM string) http.Handler {
	t.Helper()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/v1/pki/certs":
			writeJSON(t, w, map[string]any{
				"data": map[string]any{
					"keys": []string{"valid-serial", "revoked-serial"},
				},
			})
		case "/v1/pki/cert/valid-serial":
			writeJSON(t, w, map[string]any{
				"data": map[string]any{
					"certificate": validPEM,
				},
			})
		case "/v1/pki/cert/revoked-serial":
			writeJSON(t, w, map[string]any{
				"data": map[string]any{
					"certificate":             revokedPEM,
					"revocation_time_rfc3339": time.Now().Add(-time.Minute).Format(time.RFC3339),
				},
			})
		default:
			http.NotFound(w, r)
		}
	})
}

func mustAPIClient(t *testing.T, address string) *api.Client {
	t.Helper()

	cfg := api.DefaultConfig()
	cfg.Address = address

	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	return client
}

func assertDiscover(t *testing.T, service *monitor.Monitor, revoked bool, want string) {
	t.Helper()

	data, err := service.Discover(revoked)
	if err != nil {
		t.Fatalf("Discover(%t) error = %v", revoked, err)
	}

	if got := string(data); got != want {
		t.Fatalf("Discover(%t) = %s, want %s", revoked, got, want)
	}
}

func mustCertificatePEM(t *testing.T, commonName string, notBefore, notAfter time.Time) (string, *x509.Certificate) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload map[string]any) {
	t.Helper()

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
}
