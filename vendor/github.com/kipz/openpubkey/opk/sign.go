package opk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/kipz/openpubkey/oidc"
)

func CreateSigner(payload *[]byte, provider oidc.OIDCProvider) (*ECDSASigner, *CIC, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating private key: %w", err)
	}
	signer, err := NewSignerVerifier(privKey)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.Sum256(*payload)
	sig, err := signer.Sign(h[:])
	if err != nil {
		return nil, nil, err
	}
	rz := make([]byte, 32)
	rand.Read(rz)

	key := privKey.Public()

	pem, err := PubToPem(key)
	if err != nil {
		return nil, nil, err
	}
	cic := NewCIC("ES256", pem, rz, h[:], sig)
	return signer, cic, nil
}
func SignedOpenPubKey(payload *[]byte, provider oidc.OIDCProvider) (*OpenPubKey, error) {
	signer, cic, err := CreateSigner(payload, provider)
	if err != nil {
		return nil, err
	}
	claims := &oidc.Claims{
		Audience: cic.Hash(),
	}
	token, err := provider.GetJWT(claims)
	if err != nil {
		return nil, err
	}
	return NewOpenPubKey(token, *signer, cic), nil
}
