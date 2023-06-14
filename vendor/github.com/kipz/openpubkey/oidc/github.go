package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"
)

func GetEnvironmentVariable(e string) (string, error) {
	value := os.Getenv(e)
	if value == "" {
		return "", fmt.Errorf("missing %s from envrionment", e)
	}
	return value, nil
}

func quitOnErr(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func DefaultOIDCClient(audience string) ActionsOIDCClient {
	tokenURL, err := GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL")
	quitOnErr(err)
	token, err := GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	quitOnErr(err)

	c, err := NewActionsOIDCClient(tokenURL, audience, token)
	quitOnErr(err)

	return c
}

type GitHubOIDCProvider struct {
}

func (p *GitHubOIDCProvider) GetJWT(claims *Claims) (*JWT, error) {
	c := DefaultOIDCClient(claims.Audience)
	jwt, err := c.GetJWT()
	if err != nil {
		return nil, err
	}
	err = jwt.Parse()
	if err != nil {
		return nil, err
	}
	return jwt, nil
}

func (p *GitHubOIDCProvider) GetPublicKey(issueUrl string, kid string) (*rsa.PublicKey, error) {
	return GetOIDCPublicKey(issueUrl, kid)
}

func GetActionsToken(audience string) (*JWT, error) {
	c := DefaultOIDCClient(audience)
	jwt, err := c.GetJWT()
	if err != nil {
		return nil, err
	}
	jwt.Parse()
	return jwt, nil
}

type ActionsOIDCClient struct {
	// the url to fetch the jwt
	TokenRequestURL string
	// the audience for the jwt
	Audience string
	// the token used to retrieve the jwt, not the jwt
	RequestToken string
}

// construct a new ActionsOIDCClient
func NewActionsOIDCClient(tokenURL string, audience string, token string) (ActionsOIDCClient, error) {
	c := ActionsOIDCClient{
		TokenRequestURL: tokenURL,
		Audience:        audience,
		RequestToken:    token,
	}
	err := c.BuildTokenURL()
	return c, err
}

// this function uses an ActionsOIDCClient to build the complete URL
// to request a jwt
func (c *ActionsOIDCClient) BuildTokenURL() error {
	parsed_url, err := url.Parse(c.TokenRequestURL)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	if c.Audience != "" {
		query := parsed_url.Query()
		query.Set("audience", c.Audience)
		parsed_url.RawQuery = query.Encode()
		c.TokenRequestURL = parsed_url.String()
	} else {
		panic("audience is required")
	}

	return nil
}

// retrieve an actions oidc token
func (c *ActionsOIDCClient) GetJWT() (*JWT, error) {
	request, err := http.NewRequest("GET", c.TokenRequestURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Authorization", "Bearer "+c.RequestToken)

	var httpClient http.Client
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 from jwt api: %s", http.StatusText((response.StatusCode)))
	}

	rawBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var jwt JWT
	err = json.Unmarshal(rawBody, &jwt)

	return &jwt, err
}

func (j *JWT) Parse() error {
	var jwtToken *jwt.Token
	jwt.Parse(j.Value, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		jwtToken = token
		// we don't need a real check here
		return []byte{}, nil
	})
	j.ParsedToken = jwtToken
	return nil
}

func (j *JWT) PrettyPrintClaims() string {
	if claims, ok := j.ParsedToken.Claims.(jwt.MapClaims); ok {
		jsonClaims, err := json.MarshalIndent(claims, "", "  ")
		if err != nil {
			fmt.Println(fmt.Errorf("%w", err))
		}
		return string(jsonClaims)
	}
	return ""
}

func GetOIDCPublicKey(issueUrl string, kid string) (*rsa.PublicKey, error) {
	//fmt.Println("Fetching OIDC discovery URL: %s", issueUrl)

	oidcDiscResp, err := http.Get(issueUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to OIDC discovery URL: %w", err)
	}

	defer oidcDiscResp.Body.Close()

	if oidcDiscResp.StatusCode != 200 {
		return nil, fmt.Errorf("got %v from OIDC discovery URL", oidcDiscResp.StatusCode)
	}

	var oidcResp map[string]any
	decoder := json.NewDecoder(oidcDiscResp.Body)
	err = decoder.Decode(&oidcResp)
	if err != nil {
		return nil, fmt.Errorf("failed to json decode payload: %w", err)
	}

	jwksURI := oidcResp["jwks_uri"].(string)
	//log.Debugln("Fetching JWKS URL: %w", jwksURI)

	jwks, err := jwk.Fetch(context.TODO(), jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("couldn't find key %q in JWKS", kid)
	}

	var pubKey rsa.PublicKey
	err = key.Raw(&pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA key: %w", err)
	}
	return &pubKey, nil
}
