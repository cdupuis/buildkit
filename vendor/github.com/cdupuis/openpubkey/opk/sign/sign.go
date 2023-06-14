package sign

import (
	"context"
	"encoding/base64"
	"fmt"

	json "github.com/gibson042/canonicaljson-go"
	intoto "github.com/in-toto/in-toto-golang/in_toto"

	"github.com/cdupuis/openpubkey/oidc"

	"github.com/cdupuis/openpubkey/in_toto"
	"github.com/cdupuis/openpubkey/tsa"
	"github.com/kipz/openpubkey/opk"
)

func SignInTotoStatements(_ context.Context, stmts []intoto.Statement, iss string) ([]in_toto.Envelope, error) {
	provider := oidc.Providers[iss]
	if provider == nil {
		return nil, fmt.Errorf("unkown oidc provider %s", iss)
	}
	envs := make([]in_toto.Envelope, 0)
	for _, stmt := range stmts {
		payload, err := json.Marshal(stmt)
		if err != nil {
			return nil, err
		}
		jwt, err := opk.SignedOpenPubKey(&payload, provider)
		if err != nil {
			return nil, err
		}
		sig, err := json.Marshal(jwt)
		if err != nil {
			return nil, err
		}
		ts, err := tsa.CreateTimeStamp(payload)
		if err != nil {
			return nil, err
		}
		envs = append(envs, in_toto.Envelope{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     base64.StdEncoding.EncodeToString(payload),
			Signatures: []in_toto.Signature{{
				Sig: base64.StdEncoding.EncodeToString(sig),
			}, {
				Sig: base64.StdEncoding.EncodeToString(ts),
			}},
			PredicateType: stmt.PredicateType,
		})
	}
	return envs, nil
}
