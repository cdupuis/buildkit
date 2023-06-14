package opk

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/kipz/openpubkey/oidc"
)

func VerifyOPK(plain *[]byte, jwt *OpenPubKey, provider oidc.OIDCProvider, ids *[]Identity) error {
	payload, opkSignature := jwt.Payload, jwt.Signatures[1]

	cic, err := VerifyOPKSignature(opkSignature, payload)
	if err != nil {
		return fmt.Errorf("failed to verify opk signature: %w", err)
	}
	fmt.Println("Verified OPK signature", payload)
	err = VerifyOIDCSignature(jwt.Signatures[0], payload, provider, ids)
	if err != nil {
		return fmt.Errorf("failed to verify oidc signature: %w", err)
	}
	err = verifyNonce(cic, payload)
	if err != nil {
		return fmt.Errorf("failed to verify nonce: %w", err)
	}
	h := sha256.Sum256(*plain)
	if !bytes.Equal(h[:], cic.Digest) {
		return fmt.Errorf("digest doesn't match")
	}
	fmt.Println("Verified signed payload matches")
	return nil
}

func VerifyOPKSignature(sigWrapper OPKSignature, payload string) (*CIC, error) {
	protectedJSON, err := base64.RawURLEncoding.DecodeString(sigWrapper.Protected)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode protected: %w", err)
	}

	var protected CIC
	err = json.Unmarshal(protectedJSON, &protected)
	if err != nil {
		return nil, fmt.Errorf("failed to json decode our protected: %w", err)
	}

	if protected.Algorithm != "ES256" {
		return nil, fmt.Errorf("expected ES256 alg, got %q", protected.Algorithm)
	}

	pubKeyPEM := protected.PublicKey
	pubKey, err := PemToPub(pubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode our public key: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigWrapper.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode our signature: %w", err)
	}

	verifier, err := NewVerifier(pubKey.(*ecdsa.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to LoadECDSAVerifier: %w", err)
	}

	//prot := []byte(sigWrapper.Protected)
	msg := append([]byte(payload), protectedJSON...)
	err = verifier.Verify(sig, msg)
	if err != nil {
		return nil, fmt.Errorf("failed to verify our signature: %w", err)
	}

	fmt.Println("Verified signing key in OPK was used to sign OPK payload")

	return &protected, nil
}

type Identity struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

func VerifyOIDCSignature(sigWrapper OPKSignature, payloadStr string, provider oidc.OIDCProvider, ids *[]Identity) error {
	protectedJSON, err := base64.RawURLEncoding.DecodeString(sigWrapper.Protected)
	if err != nil {
		return fmt.Errorf("failed to base64 decode protected: %w", err)
	}
	//log.Debugln("Decoded protected: %s\n", string(protectedJSON))
	var protected map[string]string
	err = json.Unmarshal(protectedJSON, &protected)
	if err != nil {
		return fmt.Errorf("failed to json decode their protected: %w", err)
	}
	//log.Debugln("Unmarshalled protected: %s\n", protected)

	if protected["alg"] != "RS256" {
		return fmt.Errorf("expected RS256 alg")
	}
	//log.Debugln("Got alg %s\n", protected["alg"])
	payloadJSON, err := base64.RawURLEncoding.DecodeString(strings.Split(payloadStr, ".")[1])
	if err != nil {
		return fmt.Errorf("failed to base64 decode payload: %w", err)
	}
	//log.Debugln("Decoded payload: %s\n", string(payloadJSON))
	var payload map[string]any
	err = json.Unmarshal(payloadJSON, &payload)
	if err != nil {
		return fmt.Errorf("failed to json decode payload: %w", err)
	}

	issuer := payload["iss"].(string)
	issuerUrl, err := url.JoinPath(issuer, ".well-known/openid-configuration")
	if err != nil {
		return fmt.Errorf("failed to construct OIDC discovery URI: %w", err)
	}
	//log.Debugln("Got issuer %s\n", issuer)
	pubKey, err := provider.GetPublicKey(issuerUrl, protected["kid"])
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigWrapper.Signature)
	if err != nil {
		return fmt.Errorf("failed to base64 decode signature: %w", err)
	}

	//log.Debugln("Hashing input: ", sigWrapper.Protected, ".", strings.Split(payloadStr, ".")[1])
	signingInput := fmt.Sprint(strings.Split(payloadStr, ".")[0], ".", strings.Split(payloadStr, ".")[1])

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, SHA256([]byte(signingInput)), sig)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	fmt.Println("Verified OIDC payload was signed by", issuer)

	subject := payload["sub"].(string)
	if len(*ids) > 0 {
		for _, id := range *ids {
			if id.Issuer == issuer && id.Subject == subject {
				return nil
			}
		}
		return fmt.Errorf("none of the expected identities matched what was in the ID token, got %s from %s", subject, issuer)
	}

	return nil
}

func verifyNonce(cic *CIC, payloadStr string) error {
	payloadJSON, err := base64.RawURLEncoding.DecodeString(strings.Split(payloadStr, ".")[1])
	if err != nil {
		return fmt.Errorf("failed to base64 decode payload: %w", err)
	}

	var payload map[string]any
	err = json.Unmarshal(payloadJSON, &payload)
	//log.Debugln("Unmarshalled payload")
	if err != nil {
		return fmt.Errorf("failed to json decode payload: %w", err)
	}
	//log.Debugln("Verifying nonce in OIDC payload")
	nonce := payload["aud"].(string)

	if nonce != cic.Hash() {
		return fmt.Errorf("nonce doesn't match")
	}

	fmt.Println("Verified nonce in OIDC payload matches header")
	return nil
}
