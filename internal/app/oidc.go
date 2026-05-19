package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

type RequestLog struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

type ResponseLog struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type OIDCResult struct {
	Request  RequestLog   `json:"request"`
	Response *ResponseLog `json:"response,omitempty"`
	Error    string       `json:"error,omitempty"`
}

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

func discover(issuerURL string) (*OIDCResult, *DiscoveryDocument, error) {
	discoveryURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	result := &OIDCResult{
		Request: RequestLog{
			Method:  "GET",
			URL:     discoveryURL,
			Headers: map[string]string{"Accept": "application/json"},
		},
	}

	req, err := http.NewRequest("GET", discoveryURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result, nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.Response = &ResponseLog{
		Status:  resp.StatusCode,
		Headers: headersToMap(resp.Header),
		Body:    string(body),
	}

	if resp.StatusCode != 200 {
		err := fmt.Errorf("discovery failed with status %d", resp.StatusCode)
		result.Error = err.Error()
		return result, nil, err
	}

	var doc DiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		result.Error = err.Error()
		return result, nil, err
	}

	return result, &doc, nil
}

func exchangeCode(tokenURL, clientID, clientSecret, code, redirectURI, codeVerifier string, extra map[string]string) *OIDCResult {
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", code)
	params.Set("redirect_uri", redirectURI)
	if codeVerifier != "" {
		params.Set("code_verifier", codeVerifier)
	}
	for k, v := range extra {
		params.Set(k, v)
	}
	return doTokenRequest(tokenURL, clientID, clientSecret, params)
}

func refreshToken(tokenURL, clientID, clientSecret, refreshTok string, extra map[string]string) *OIDCResult {
	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("refresh_token", refreshTok)
	for k, v := range extra {
		params.Set(k, v)
	}
	return doTokenRequest(tokenURL, clientID, clientSecret, params)
}

func doTokenRequest(tokenURL, clientID, clientSecret string, params url.Values) *OIDCResult {
	bodyStr := params.Encode()

	result := &OIDCResult{
		Request: RequestLog{
			Method: "POST",
			URL:    tokenURL,
			Headers: map[string]string{
				"Content-Type":  "application/x-www-form-urlencoded",
				"Accept":        "application/json",
				"Authorization": "Basic <redacted>",
			},
			Body: bodyStr,
		},
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(bodyStr))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	result.Response = &ResponseLog{
		Status:  resp.StatusCode,
		Headers: headersToMap(resp.Header),
		Body:    string(respBody),
	}

	return result
}

func getUserInfo(userinfoURL, accessToken string) *OIDCResult {
	result := &OIDCResult{
		Request: RequestLog{
			Method: "GET",
			URL:    userinfoURL,
			Headers: map[string]string{
				"Authorization": "Bearer <redacted>",
				"Accept":        "application/json",
			},
		},
	}

	req, err := http.NewRequest("GET", userinfoURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.Response = &ResponseLog{
		Status:  resp.StatusCode,
		Headers: headersToMap(resp.Header),
		Body:    string(body),
	}

	return result
}

func introspectToken(introspectionURL, clientID, clientSecret, token, tokenTypeHint string) *OIDCResult {
	params := url.Values{}
	params.Set("token", token)
	if tokenTypeHint != "" {
		params.Set("token_type_hint", tokenTypeHint)
	}
	bodyStr := params.Encode()

	result := &OIDCResult{
		Request: RequestLog{
			Method: "POST",
			URL:    introspectionURL,
			Headers: map[string]string{
				"Content-Type":  "application/x-www-form-urlencoded",
				"Authorization": "Basic <redacted>",
			},
			Body: bodyStr,
		},
	}

	req, err := http.NewRequest("POST", introspectionURL, strings.NewReader(bodyStr))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	result.Response = &ResponseLog{
		Status:  resp.StatusCode,
		Headers: headersToMap(resp.Header),
		Body:    string(respBody),
	}

	return result
}

func decodeJWT(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT: expected at least 2 parts, got %d", len(parts))
	}

	result := make(map[string]interface{})

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	var header interface{}
	_ = json.Unmarshal(headerBytes, &header)
	result["header"] = header

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}
	var payload interface{}
	_ = json.Unmarshal(payloadBytes, &payload)
	result["payload"] = payload

	if len(parts) == 3 {
		result["signature"] = parts[2]
	}

	return result, nil
}

func headersToMap(h http.Header) map[string]string {
	m := make(map[string]string)
	for k, v := range h {
		m[k] = strings.Join(v, ", ")
	}
	return m
}
