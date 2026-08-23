package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// testIDP is an in-process OIDC test double that serves discovery, JWKS, and
// token endpoints. It mints signed ID tokens with a known RSA key.
type testIDP struct {
	*httptest.Server
	t   *testing.T
	key *rsa.PrivateKey
	mu  sync.Mutex
	// tokenResponse is the JSON body returned by the token endpoint.
	tokenResponse map[string]interface{}
	// tokenStatus is the HTTP status returned by the token endpoint.
	tokenStatus int
}

func newTestIDP(t *testing.T) *testIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	idp := &testIDP{
		t:           t,
		key:         key,
		mu:          sync.Mutex{},
		tokenStatus: http.StatusOK,
	}

	idp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/openid-configuration":
			idp.serveDiscovery(w)
		case r.URL.Path == "/jwks":
			idp.serveJWKS(w)
		case r.URL.Path == "/token":
			idp.serveToken(w, r)
		default:
			http.NotFound(w, r)
		}
	}))

	t.Cleanup(idp.Close)
	return idp
}

func (idp *testIDP) serveDiscovery(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	doc := map[string]interface{}{
		"issuer":                                idp.URL,
		"jwks_uri":                              idp.URL + "/jwks",
		"authorization_endpoint":                idp.URL + "/auth",
		"token_endpoint":                        idp.URL + "/token",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	json.NewEncoder(w).Encode(doc)
}

func (idp *testIDP) serveJWKS(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")

	pub := idp.key.Public().(*rsa.PublicKey)
	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": "test-key",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}
	json.NewEncoder(w).Encode(jwks)
}

func (idp *testIDP) serveToken(w http.ResponseWriter, r *http.Request) {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if idp.tokenStatus != http.StatusOK {
		w.WriteHeader(idp.tokenStatus)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	json.NewEncoder(w).Encode(idp.tokenResponse)
}

// setTokenResponse sets the token endpoint response for the next callback.
func (idp *testIDP) setTokenResponse(resp map[string]interface{}, status int) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.tokenResponse = resp
	idp.tokenStatus = status
}

// mintIDToken creates a signed JWT ID token with the given claims.
func (idp *testIDP) mintIDToken(claims map[string]interface{}) string {
	// Add standard OIDC claims
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = idp.URL
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = []string{"test-client"}
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(1 * time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}

	header := map[string]string{
		"alg": "RS256",
		"kid": "test-key",
		"typ": "JWT",
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)

	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, hash[:])
	if err != nil {
		idp.t.Fatalf("failed to sign token: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// mintValidTokenResponse returns a token response map containing a valid
// signed ID token for the given user claims.
func (idp *testIDP) mintValidTokenResponse(userClaims map[string]interface{}) map[string]interface{} {
	// Add required claims
	if userClaims == nil {
		userClaims = make(map[string]interface{})
	}
	userClaims["sub"] = "test-user-123"
	userClaims["email"] = "testuser@example.com"
	userClaims["email_verified"] = true
	userClaims["preferred_username"] = "testuser"
	userClaims["given_name"] = "Test"
	userClaims["family_name"] = "User"

	idToken := idp.mintIDToken(userClaims)
	return map[string]interface{}{
		"access_token":  "test-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "test-refresh-token",
		"id_token":      idToken,
	}
}
