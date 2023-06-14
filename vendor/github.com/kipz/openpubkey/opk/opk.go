package opk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/kipz/openpubkey/oidc"
)

type OpenPubKey struct {
	Payload    string         `json:"payload"`
	Signatures []OPKSignature `json:"signatures"`
}

type OPKSignature struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

type CIC struct {
	Algorithm   string `json:"alg"`
	PublicKey   []byte `json:"pub"`
	RandomNoise []byte `json:"rz"`
	Digest      []byte `json:"digest"`
	Signature   []byte `json:"sig"`
	Timestamp   []byte `json:"timestamp"`
}

func NewKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func PubToPem(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: b,
		},
	), nil
}

func PemToPub(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM block from %q", pemBytes)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func PrivToPem(priv *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	))
}

func SHA512(things ...[]byte) []byte {
	sha := sha512.New()
	for _, thing := range things {
		sha.Write(thing)
	}
	return sha.Sum(nil)
}

func SHA3(things ...[]byte) []byte {
	sha := sha3.New512()
	for _, thing := range things {
		sha.Write(thing)
	}
	return sha.Sum(nil)
}

func SHA256(things ...[]byte) []byte {
	sha := sha256.New()
	for _, thing := range things {
		sha.Write(thing)
	}
	return sha.Sum(nil)
}

func NewCIC(alg string, pub, noise []byte, digest []byte, sig []byte) *CIC {
	return &CIC{
		Algorithm:   alg,
		PublicKey:   pub,
		RandomNoise: noise,
		Signature:   sig,
		Digest:      digest,
		Timestamp:   []byte(time.Now().Format(time.RFC3339))}
}

func (c *CIC) Hash() string {
	sha := SHA3([]byte(c.Algorithm), c.PublicKey, c.RandomNoise, c.Signature, c.Digest, c.Timestamp)
	return hex.EncodeToString(sha)
}

type ECDSASigner struct {
	priv *ecdsa.PrivateKey
}

func NewSignerVerifier(priv *ecdsa.PrivateKey) (*ECDSASigner, error) {
	return &ECDSASigner{
		priv: priv,
	}, nil
}

type ECDSAVerifier struct {
	publicKey *ecdsa.PublicKey
}

func NewVerifier(pub *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	return &ECDSAVerifier{
		publicKey: pub,
	}, nil
}

func (e ECDSAVerifier) Verify(signature, message []byte) error {
	if e.publicKey == nil {
		return errors.New("no public key set for ECDSAVerifier")
	}

	digest := SHA256(message)

	if !ecdsa.VerifyASN1(e.publicKey, digest, signature) {
		return errors.New("invalid signature for ECDSAVerifier")
	}
	return nil
}

func (e ECDSASigner) SignOPK(payload string, opkHeader []byte) ([]byte, error) {
	digest := SHA256([]byte(payload), opkHeader)
	return ecdsa.SignASN1(rand.Reader, e.priv, digest)
}

func (e ECDSASigner) Sign(payload []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, e.priv, payload)
}

func NewOpenPubKey(jwt *oidc.JWT, sv ECDSASigner, cic *CIC) *OpenPubKey {
	header, _ := json.Marshal(jwt.ParsedToken.Header)
	opkHeader, _ := json.Marshal(cic)
	payload := jwt.ParsedToken.Raw
	opkSig, err := sv.SignOPK(payload, opkHeader)
	if err != nil {
		panic(err)
	}
	return &OpenPubKey{
		Payload: payload,
		Signatures: []OPKSignature{
			{

				Protected: base64.RawURLEncoding.EncodeToString(header),
				Signature: jwt.ParsedToken.Signature,
			},
			{
				Protected: base64.RawURLEncoding.EncodeToString(opkHeader),
				Signature: base64.RawURLEncoding.EncodeToString(opkSig),
			},
		},
	}
}
