package in_toto

import (
	"encoding/json"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

type Signature struct {
	Sig string `json:"sig"`
}

type Statement struct {
	intoto.StatementHeader
	Predicate json.RawMessage `json:"predicate"`
}

type Envelope struct {
	PayloadType   string      `json:"payloadType"`
	Payload       string      `json:"payload"`
	Signatures    []Signature `json:"signatures"`
	PredicateType string      `json:"-"`
}
