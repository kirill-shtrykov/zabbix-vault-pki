package monitor

import (
	"crypto/x509"
	"time"
)

type Certificate struct {
	Serial     string
	Cert       *x509.Certificate
	Revocation time.Time
}

func (c *Certificate) IsValid() bool {
	now := time.Now()

	if now.Before(c.Cert.NotBefore) || now.After(c.Cert.NotAfter) {
		return false
	}

	return true
}

func (c *Certificate) IsRevoked() bool {
	return !c.Revocation.IsZero()
}
