package monitor

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"path"

	"github.com/hashicorp/vault/api"
)

const (
	DefaultListPath = "pki/certs"
	DefaultCertPath = "pki/cert"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrKeysType  = errors.New("unexpected data type for keys")
	ErrDecodePEM = errors.New("failed to decode PEM block")
)

type Monitor struct {
	client *api.Client
}

func (m *Monitor) list() ([]string, error) {
	secret, err := m.client.Logical().List(DefaultListPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, nil
	}

	keysRaw, ok := secret.Data["keys"]
	if !ok {
		return nil, nil
	}

	keysIface, ok := keysRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: %T", ErrKeysType, keysRaw)
	}

	keys := make([]string, 0, len(keysIface))

	for _, k := range keysIface {
		if s, ok := k.(string); ok {
			keys = append(keys, s)
		}
	}

	return keys, nil
}

func (m *Monitor) certificate(serial string) (*Certificate, error) {
	certPath := path.Join(DefaultCertPath, serial)

	secret, err := m.client.Logical().Read(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate %s: %w", serial, err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: certificate %s not found", ErrNotFound, serial)
	}

	cert := &Certificate{Serial: serial}

	pemStr, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: certificate field not found or not a string", ErrNotFound)
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("%w", ErrDecodePEM)
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	cert.Cert = parsedCert

	return cert, nil
}

func (m *Monitor) certificates(serials []string) ([]*Certificate, error) {
	var certs []*Certificate

	for _, serial := range serials {
		cert, err := m.certificate(serial)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate '%s': %w", serial, err)
		}

		if cert.isValid() {
			certs = append(certs, cert)
		}
	}

	return certs, nil
}

func (m *Monitor) Discovery() ([]byte, error) {
	serials, err := m.list()
	if err != nil {
		return nil, err
	}

	certs, err := m.certificates(serials)
	if err != nil {
		return nil, err
	}

	resp := &LLDResponse{
		Data: make([]LLDItem, 0, len(certs)),
	}

	for _, cert := range certs {
		resp.Data = append(resp.Data, LLDItem{SN: cert.Serial, CN: cert.Cert.Subject.CommonName})
	}

	b, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return b, nil
}

func (m *Monitor) Expiry(serial string) (int64, error) {
	cert, err := m.certificate(serial)
	if err != nil {
		return -1, err
	}

	return cert.Cert.NotAfter.Unix(), err
}

func New(client *api.Client) *Monitor {
	return &Monitor{client: client}
}
