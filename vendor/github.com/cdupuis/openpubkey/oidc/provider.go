package oidc

import (
	"github.com/kipz/openpubkey/oidc"
)

var (
	Providers = map[string]oidc.OIDCProvider{
		"https://token.actions.githubusercontent.com": &oidc.GitHubOIDCProvider{},
	}
)
