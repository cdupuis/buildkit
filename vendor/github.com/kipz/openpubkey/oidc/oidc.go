package oidc

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt"
)

type GetOIDCToken func(audience string) (*JWT, error)

type Claims struct {
	Audience string `json:"aud"`
}

type JWT struct {
	Count       int
	Value       string
	ParsedToken *jwt.Token
}

type OIDCProvider interface {
	GetJWT(*Claims) (*JWT, error)
	GetPublicKey(string, string) (*rsa.PublicKey, error)
}
