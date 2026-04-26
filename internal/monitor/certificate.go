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

func (c *Certificate) IsValid(revoked bool) bool {
	now := time.Now()

	if now.Before(c.Cert.NotBefore) || now.After(c.Cert.NotAfter) {
		return false
	}

	if !c.Revocation.IsZero() && !revoked {
		return false
	}

	return true
}
