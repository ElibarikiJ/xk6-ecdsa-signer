package ecdsa

import (
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/ecdsa", new(ECDSA))
}

type ECDSA struct{}

// Sign returns a base64 signature for a given message using a PEM private key
func (e *ECDSA) Sign(message string, privKeyPem string) string {
	privKey := privatekey.FromPem(privKeyPem)
	signature := ecdsa.Sign(message, &privKey)
	return signature.ToBase64()
}
