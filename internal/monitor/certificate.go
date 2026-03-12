package monitor

import (
	"crypto/x509"
	"time"
)

type Certificate struct {
	Serial string
	Cert   *x509.Certificate
}

func (c *Certificate) isValid() bool {
	now := time.Now()

	if now.Before(c.Cert.NotBefore) || now.After(c.Cert.NotAfter) {
		return false
	}

	return true
}
