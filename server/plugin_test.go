package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/mattermost/mattermost/server/public/model"
	"golang.org/x/oauth2"
)

// --- Mock API ---

type mockAPI struct {
	config           *model.Config
	loadedConfig     *pluginConfig
	usersByEmail     map[string]*model.User
	usersByUsername  map[string]*model.User
	createdUser      *model.User
	createdSession   *model.Session
	createUserErr    *model.AppError
	createSessionErr *model.AppError
}

func newMockAPI() *mockAPI {
	return &mockAPI{
		config: &model.Config{
			ServiceSettings: model.ServiceSettings{
				SiteURL:            model.NewPointer("http://localhost:8065"),
				ConnectionSecurity: model.NewPointer("https"),
			},
		},
		usersByEmail:    make(map[string]*model.User),
		usersByUsername: make(map[string]*model.User),
	}
}

func (m *mockAPI) LoadPluginConfiguration(dest interface{}) error {
	if pc, ok := dest.(*pluginConfig); ok && m.loadedConfig != nil {
		*pc = *m.loadedConfig
	}
	return nil
}

func (m *mockAPI) GetConfig() *model.Config {
	return m.config
}

func (m *mockAPI) LogInfo(message string, keyValuePairs ...interface{}) {}

func (m *mockAPI) LogWarn(message string, keyValuePairs ...interface{}) {}

func (m *mockAPI) LogError(message string, keyValuePairs ...interface{}) {}

func (m *mockAPI) GetUserByEmail(email string) (*model.User, *model.AppError) {
	if u, ok := m.usersByEmail[email]; ok {
		return u, nil
	}
	return nil, model.NewAppError("mock", "user.get_by_email.not_found", nil, "", http.StatusNotFound)
}

func (m *mockAPI) GetUserByUsername(username string) (*model.User, *model.AppError) {
	if u, ok := m.usersByUsername[username]; ok {
		return u, nil
	}
	return nil, model.NewAppError("mock", "user.get_by_username.not_found", nil, "", http.StatusNotFound)
}

func (m *mockAPI) CreateUser(user *model.User) (*model.User, *model.AppError) {
	if m.createUserErr != nil {
		return nil, m.createUserErr
	}
	user.Id = model.NewId()
	user.Email = strings.ToLower(user.Email)
	m.createdUser = user
	m.usersByEmail[user.Email] = user
	m.usersByUsername[user.Username] = user
	return user, nil
}

// CreateSession mirrors production semantics: it stores and returns a
// populated copy, leaving the caller's struct untouched (M-3). A regression
// that reads the token off the input struct would produce an empty cookie
// value and fail the assertions in successful_new_user_provisioning.
func (m *mockAPI) CreateSession(session *model.Session) (*model.Session, *model.AppError) {
	if m.createSessionErr != nil {
		return nil, m.createSessionErr
	}
	created := *session
	created.Token = model.NewId()
	m.createdSession = &created
	return &created, nil
}

// --- Existing tests ---

func TestGenerateUsername(t *testing.T) {
	p := &Plugin{}

	tests := []struct {
		input    string
		expected string
	}{
		{"john_doe", "john_doe"},
		{"John Doe", "johndoe"},
		{"Jöhn", "jhn"},
		{"test@domain", "testdomain"},
		{"  spaced  ", "spaced"},
		{"---leading", "leading"},
		{"trailing---", "trailing"},
		{"_under_score", "under_score"},
		{"", ""},
		{"a", "a"},
		{strings.Repeat("a", 70), strings.Repeat("a", 70)},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := p.generateUsername(tc.input)
			if got != tc.expected {
				t.Errorf("generateUsername(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestCleanUsername(t *testing.T) {
	p := &Plugin{}

	tests := []struct {
		input    string
		expected string
	}{
		{"validUser", "validUser"},
		{"1invalid", "u1invalid"},
		{"_start", "u_start"},
		{"short", "short"},
		{strings.Repeat("a", 70), strings.Repeat("a", 64)},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := p.cleanUsername(tc.input)
			if got != tc.expected {
				t.Errorf("cleanUsername(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestCleanUsernameStartsWithLetter(t *testing.T) {
	p := &Plugin{}
	usernames := []string{"123abc", "_bad", "-hyphen", "good123"}
	for _, u := range usernames {
		cleaned := p.cleanUsername(u)
		first := cleaned[0]
		if (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') {
			continue
		}
		t.Errorf("cleaned username %q does not start with a letter", cleaned)
	}
}

// --- /login route tests ---

func TestPlugin_Login(t *testing.T) {
	t.Run("happy_path_redirects_to_idp_with_state", func(t *testing.T) {
		idp := newTestIDP(t)

		oidcProvider, err := oidc.NewProvider(context.Background(), idp.URL)
		if err != nil {
			t.Fatalf("failed to create OIDC provider: %v", err)
		}

		mock := newMockAPI()
		p := &Plugin{api: mock}
		p.provider = &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8065/plugins/com.mattermost.dex/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     oidcProvider.Endpoint(),
		}
		p.verifier = oidcProvider.Verifier(&oidc.Config{ClientID: "test-client"})

		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/login", nil)
		w := httptest.NewRecorder()

		p.handleLogin(w, req)

		// Check 302 redirect
		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}

		// Check Location header contains required params
		loc := w.Header().Get("Location")
		if loc == "" {
			t.Fatal("expected Location header")
		}

		locURL, err := url.Parse(loc)
		if err != nil {
			t.Fatalf("invalid Location URL: %v", err)
		}

		q := locURL.Query()
		if q.Get("client_id") != "test-client" {
			t.Errorf("expected client_id=test-client, got %q", q.Get("client_id"))
		}
		if q.Get("response_type") != "code" {
			t.Errorf("expected response_type=code, got %q", q.Get("response_type"))
		}
		if q.Get("scope") == "" {
			t.Error("expected scope parameter")
		}
		stateParam := q.Get("state")
		if stateParam == "" {
			t.Error("expected state parameter in redirect URL")
		}
		if q.Get("redirect_uri") != "http://localhost:8065/plugins/com.mattermost.dex/callback" {
			t.Errorf("unexpected redirect_uri %q", q.Get("redirect_uri"))
		}

		// The redirect must target the IdP's authorization endpoint
		idpHost, err := url.Parse(idp.URL)
		if err != nil {
			t.Fatalf("failed to parse IdP URL: %v", err)
		}
		if locURL.Host != idpHost.Host || locURL.Path != "/auth" {
			t.Errorf("expected redirect to the IdP authorization endpoint (%s/auth), got %s%s", idpHost.Host, locURL.Host, locURL.Path)
		}

		// Check state cookie matches the URL state
		cookies := w.Result().Cookies()
		var stateCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == cookieStateKey {
				stateCookie = c
			}
		}
		if stateCookie == nil {
			t.Fatal("expected state cookie to be set")
		}
		if stateCookie.Value != stateParam {
			t.Errorf("state cookie %q != state in URL %q", stateCookie.Value, stateParam)
		}
		if !stateCookie.HttpOnly {
			t.Error("state cookie should be HttpOnly")
		}
		if !stateCookie.Secure {
			t.Error("state cookie should be Secure (mock defaults to https)")
		}
	})

	t.Run("plain_http_state_cookie_not_secure", func(t *testing.T) {
		idp := newTestIDP(t)

		oidcProvider, err := oidc.NewProvider(context.Background(), idp.URL)
		if err != nil {
			t.Fatalf("failed to create OIDC provider: %v", err)
		}

		mock := newMockAPI()
		mock.config.ServiceSettings.ConnectionSecurity = model.NewPointer("http")
		p := &Plugin{api: mock}
		p.provider = &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8065/plugins/com.mattermost.dex/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     oidcProvider.Endpoint(),
		}
		p.verifier = oidcProvider.Verifier(&oidc.Config{ClientID: "test-client"})

		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/login", nil)
		w := httptest.NewRecorder()

		p.handleLogin(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}

		var stateCookie *http.Cookie
		for _, c := range w.Result().Cookies() {
			if c.Name == cookieStateKey {
				stateCookie = c
			}
		}
		if stateCookie == nil {
			t.Fatal("expected state cookie to be set")
		}
		if stateCookie.Secure {
			t.Error("state cookie should not be Secure on plain HTTP")
		}
	})

	t.Run("config_error_when_provider_nil", func(t *testing.T) {
		mock := newMockAPI()
		p := &Plugin{api: mock}
		// provider is nil

		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/login", nil)
		w := httptest.NewRecorder()

		p.handleLogin(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}

		loc := w.Header().Get("Location")
		if loc != "/login?error=config_error" {
			t.Errorf("expected redirect to /login?error=config_error, got %q", loc)
		}

		// No state cookie should be set
		for _, c := range w.Result().Cookies() {
			if c.Name == cookieStateKey {
				t.Error("state cookie should not be set on config error")
			}
		}
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		mock := newMockAPI()
		p := &Plugin{api: mock}

		req := httptest.NewRequest(http.MethodPost, "/plugins/com.mattermost.dex/login", nil)
		w := httptest.NewRecorder()

		p.handleLogin(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", w.Code)
		}
	})
}

// --- Public config tests ---

func TestGetPluginPublicConfig(t *testing.T) {
	t.Run("returns_camelCase_keys", func(t *testing.T) {
		mock := newMockAPI()
		p := &Plugin{api: mock}
		p.config = pluginConfig{
			IssuerURL:   "https://dex.example.com",
			ClientID:    "mattermost",
			ButtonLabel: "Sign in with Dex",
			ButtonColor: "#009EDB",
			RedirectURL: "https://mm.example.com/plugins/com.mattermost.dex/callback",
		}

		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/api/public-config", nil)
		w := httptest.NewRecorder()

		p.GetPluginPublicConfig(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Verify the exact camelCase key set: the five expected keys, no more
		expectedKeys := []string{"issuerUrl", "clientId", "buttonLabel", "buttonColor", "redirectUrl"}
		if len(resp) != len(expectedKeys) {
			t.Errorf("expected exactly %d keys, got %d: %v", len(expectedKeys), len(resp), resp)
		}
		for _, key := range expectedKeys {
			if _, ok := resp[key]; !ok {
				t.Errorf("expected key %q to be present", key)
			}
		}

		// Verify no secret leaked
		for key := range resp {
			if strings.Contains(key, "secret") || strings.Contains(key, "Secret") {
				t.Errorf("secret field %q should not be in public config", key)
			}
		}

		if resp["issuerUrl"] != "https://dex.example.com" {
			t.Errorf("issuerUrl = %q, want %q", resp["issuerUrl"], "https://dex.example.com")
		}
		if resp["clientId"] != "mattermost" {
			t.Errorf("clientId = %q, want %q", resp["clientId"], "mattermost")
		}
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		mock := newMockAPI()
		p := &Plugin{api: mock}

		req := httptest.NewRequest(http.MethodPost, "/plugins/com.mattermost.dex/api/public-config", nil)
		w := httptest.NewRecorder()

		p.GetPluginPublicConfig(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", w.Code)
		}
	})
}

// --- OnConfigurationChange tests ---

func TestOnConfigurationChange_RedirectURL(t *testing.T) {
	t.Run("auto_fill_uses_correct_plugin_id", func(t *testing.T) {
		mock := newMockAPI()
		mock.loadedConfig = &pluginConfig{
			IssuerURL:    "https://dex.example.com",
			ClientID:     "mattermost",
			ClientSecret: "secret",
			ButtonLabel:  "Sign in with Dex",
			ButtonColor:  "#009EDB",
			// RedirectURL intentionally empty to test auto-fill
		}

		p := &Plugin{api: mock}
		if err := p.OnConfigurationChange(); err != nil {
			t.Fatalf("OnConfigurationChange failed: %v", err)
		}

		expected := "http://localhost:8065/plugins/com.mattermost.dex/callback"
		if p.config.RedirectURL != expected {
			t.Errorf("RedirectURL = %q, want %q", p.config.RedirectURL, expected)
		}
	})

	t.Run("explicit_redirect_url_wins", func(t *testing.T) {
		mock := newMockAPI()
		mock.loadedConfig = &pluginConfig{
			IssuerURL:    "https://dex.example.com",
			ClientID:     "mattermost",
			ClientSecret: "secret",
			RedirectURL:  "https://custom.example.com/dex/callback",
		}

		p := &Plugin{api: mock}
		if err := p.OnConfigurationChange(); err != nil {
			t.Fatalf("OnConfigurationChange failed: %v", err)
		}

		if p.config.RedirectURL != "https://custom.example.com/dex/callback" {
			t.Errorf("RedirectURL = %q, want explicit value preserved", p.config.RedirectURL)
		}
	})
}

// --- Callback tests ---

func TestHandleCallback(t *testing.T) {
	t.Run("state_mismatch_redirects_to_invalid_state", func(t *testing.T) {
		mock := newMockAPI()
		p := &Plugin{api: mock}

		// Set a cookie with one state, send request with a different one
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?state=evil&code=abc", nil)
		req.AddCookie(&http.Cookie{Name: cookieStateKey, Value: "legitimate"})
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/login?error=invalid_state" {
			t.Errorf("expected /login?error=invalid_state, got %q", loc)
		}
	})

	t.Run("missing_state_redirects_to_invalid_request", func(t *testing.T) {
		mock := newMockAPI()
		p := &Plugin{api: mock}

		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?code=abc", nil)
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/login?error=invalid_request" {
			t.Errorf("expected /login?error=invalid_request, got %q", loc)
		}
	})

	t.Run("missing_code_redirects_to_no_code", func(t *testing.T) {
		mock := newMockAPI()
		p := &Plugin{api: mock}

		state := "test-state-value"
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?state="+state, nil)
		req.AddCookie(&http.Cookie{Name: cookieStateKey, Value: state})
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/login?error=no_code" {
			t.Errorf("expected /login?error=no_code, got %q", loc)
		}
	})

	t.Run("token_exchange_failure", func(t *testing.T) {
		idp := newTestIDP(t)
		idp.setTokenResponse(map[string]interface{}{"error": "invalid_grant"}, http.StatusBadRequest)

		oidcProvider, err := oidc.NewProvider(context.Background(), idp.URL)
		if err != nil {
			t.Fatalf("failed to create OIDC provider: %v", err)
		}

		mock := newMockAPI()
		p := &Plugin{api: mock}
		p.provider = &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     oidcProvider.Endpoint(),
		}
		p.verifier = oidcProvider.Verifier(&oidc.Config{ClientID: "test-client"})

		state := "test-state"
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?state="+state+"&code=bad-code", nil)
		req.AddCookie(&http.Cookie{Name: cookieStateKey, Value: state})
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/login?error=token_exchange_failed" {
			t.Errorf("expected /login?error=token_exchange_failed, got %q", loc)
		}
	})

	t.Run("invalid_token_signature", func(t *testing.T) {
		idp := newTestIDP(t)

		// Create a token signed with a DIFFERENT key (wrong signature)
		wrongIDP := newTestIDP(t)
		idp.setTokenResponse(wrongIDP.mintValidTokenResponse(nil), http.StatusOK)

		oidcProvider, err := oidc.NewProvider(context.Background(), idp.URL)
		if err != nil {
			t.Fatalf("failed to create OIDC provider: %v", err)
		}

		mock := newMockAPI()
		p := &Plugin{api: mock}
		p.provider = &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     oidcProvider.Endpoint(),
		}
		p.verifier = oidcProvider.Verifier(&oidc.Config{ClientID: "test-client"})

		state := "test-state"
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?state="+state+"&code=fake-code", nil)
		req.AddCookie(&http.Cookie{Name: cookieStateKey, Value: state})
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/login?error=invalid_token" {
			t.Errorf("expected /login?error=invalid_token, got %q", loc)
		}
	})

	t.Run("successful_new_user_provisioning", func(t *testing.T) {
		idp := newTestIDP(t)
		idp.setTokenResponse(idp.mintValidTokenResponse(nil), http.StatusOK)

		oidcProvider, err := oidc.NewProvider(context.Background(), idp.URL)
		if err != nil {
			t.Fatalf("failed to create OIDC provider: %v", err)
		}

		mock := newMockAPI()
		p := &Plugin{api: mock}
		p.provider = &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     oidcProvider.Endpoint(),
		}
		p.verifier = oidcProvider.Verifier(&oidc.Config{ClientID: "test-client"})

		state := "test-state"
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?state="+state+"&code=valid-code", nil)
		req.AddCookie(&http.Cookie{Name: cookieStateKey, Value: state})
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		// Should redirect to /
		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/" {
			t.Errorf("expected redirect to /, got %q", loc)
		}

		// Verify user was created
		if mock.createdUser == nil {
			t.Fatal("expected CreateUser to be called")
		}
		if mock.createdUser.Email != "testuser@example.com" {
			t.Errorf("email = %q, want testuser@example.com", mock.createdUser.Email)
		}
		if mock.createdUser.AuthService != "oauth" {
			t.Errorf("AuthService = %q, want oauth", mock.createdUser.AuthService)
		}
		if len(mock.createdUser.Password) == 0 {
			t.Error("expected non-empty password")
		}
		if !mock.createdUser.EmailVerified {
			t.Error("expected EmailVerified=true on created user")
		}

		// Verify session was created
		if mock.createdSession == nil {
			t.Fatal("expected CreateSession to be called")
		}
		if mock.createdSession.Token == "" {
			t.Error("expected session token to be set")
		}

		// Verify MMAUTHTOKEN cookie was set
		cookies := w.Result().Cookies()
		var authCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == cookieSessionTokenKey {
				authCookie = c
			}
		}
		if authCookie == nil {
			t.Fatal("expected MMAUTHTOKEN cookie to be set")
		}
		if authCookie.Value != mock.createdSession.Token {
			t.Error("cookie token should match session token")
		}
		if !authCookie.HttpOnly {
			t.Error("MMAUTHTOKEN cookie should be HttpOnly")
		}

		// Verify the state cookie was cleared after a successful callback
		var clearedState *http.Cookie
		for _, c := range cookies {
			if c.Name == cookieStateKey {
				clearedState = c
			}
		}
		if clearedState == nil {
			t.Fatal("expected the state cookie to be cleared after callback")
		}
		if clearedState.MaxAge != -1 {
			t.Errorf("cleared state cookie MaxAge = %d, want -1", clearedState.MaxAge)
		}
		if clearedState.Value != "" {
			t.Errorf("cleared state cookie Value = %q, want empty", clearedState.Value)
		}
	})

	t.Run("existing_user_no_create", func(t *testing.T) {
		idp := newTestIDP(t)
		idp.setTokenResponse(idp.mintValidTokenResponse(nil), http.StatusOK)

		oidcProvider, err := oidc.NewProvider(context.Background(), idp.URL)
		if err != nil {
			t.Fatalf("failed to create OIDC provider: %v", err)
		}

		existingUser := &model.User{
			Id:       model.NewId(),
			Email:    "testuser@example.com",
			Username: "testuser",
			Roles:    "system_user",
		}

		mock := newMockAPI()
		mock.usersByEmail["testuser@example.com"] = existingUser
		p := &Plugin{api: mock}
		p.provider = &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     oidcProvider.Endpoint(),
		}
		p.verifier = oidcProvider.Verifier(&oidc.Config{ClientID: "test-client"})

		state := "test-state"
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?state="+state+"&code=valid-code", nil)
		req.AddCookie(&http.Cookie{Name: cookieStateKey, Value: state})
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}

		// CreateUser should NOT have been called
		if mock.createdUser != nil {
			t.Error("CreateUser should not be called for existing user")
		}

		// Session should be created for the existing user
		if mock.createdSession == nil {
			t.Fatal("expected CreateSession to be called")
		}
		if mock.createdSession.UserId != existingUser.Id {
			t.Errorf("session.UserId = %q, want %q", mock.createdSession.UserId, existingUser.Id)
		}
	})

	t.Run("plain_http_auth_cookie_not_secure", func(t *testing.T) {
		idp := newTestIDP(t)
		idp.setTokenResponse(idp.mintValidTokenResponse(nil), http.StatusOK)

		oidcProvider, err := oidc.NewProvider(context.Background(), idp.URL)
		if err != nil {
			t.Fatalf("failed to create OIDC provider: %v", err)
		}

		mock := newMockAPI()
		mock.config.ServiceSettings.ConnectionSecurity = model.NewPointer("http")
		p := &Plugin{api: mock}
		p.provider = &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     oidcProvider.Endpoint(),
		}
		p.verifier = oidcProvider.Verifier(&oidc.Config{ClientID: "test-client"})

		state := "test-state"
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?state="+state+"&code=valid-code", nil)
		req.AddCookie(&http.Cookie{Name: cookieStateKey, Value: state})
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/" {
			t.Fatalf("expected redirect to /, got %q", loc)
		}

		var authCookie *http.Cookie
		for _, c := range w.Result().Cookies() {
			if c.Name == cookieSessionTokenKey {
				authCookie = c
			}
		}
		if authCookie == nil {
			t.Fatal("expected MMAUTHTOKEN cookie to be set")
		}
		if authCookie.Secure {
			t.Error("MMAUTHTOKEN cookie should not be Secure on plain HTTP")
		}
	})

	t.Run("no_id_token_redirects", func(t *testing.T) {
		idp := newTestIDP(t)
		// Token response without an id_token key
		idp.setTokenResponse(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}, http.StatusOK)

		oidcProvider, err := oidc.NewProvider(context.Background(), idp.URL)
		if err != nil {
			t.Fatalf("failed to create OIDC provider: %v", err)
		}

		mock := newMockAPI()
		p := &Plugin{api: mock}
		p.provider = &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     oidcProvider.Endpoint(),
		}
		p.verifier = oidcProvider.Verifier(&oidc.Config{ClientID: "test-client"})

		state := "test-state"
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?state="+state+"&code=valid-code", nil)
		req.AddCookie(&http.Cookie{Name: cookieStateKey, Value: state})
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/login?error=no_id_token" {
			t.Errorf("expected /login?error=no_id_token, got %q", loc)
		}
	})

	t.Run("create_user_failure_redirects", func(t *testing.T) {
		idp := newTestIDP(t)
		idp.setTokenResponse(idp.mintValidTokenResponse(nil), http.StatusOK)

		oidcProvider, err := oidc.NewProvider(context.Background(), idp.URL)
		if err != nil {
			t.Fatalf("failed to create OIDC provider: %v", err)
		}

		mock := newMockAPI()
		mock.createUserErr = model.NewAppError("mock", "mock.create_user_failure", nil, "", http.StatusInternalServerError)
		p := &Plugin{api: mock}
		p.provider = &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     oidcProvider.Endpoint(),
		}
		p.verifier = oidcProvider.Verifier(&oidc.Config{ClientID: "test-client"})

		state := "test-state"
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?state="+state+"&code=valid-code", nil)
		req.AddCookie(&http.Cookie{Name: cookieStateKey, Value: state})
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/login?error=user_error" {
			t.Errorf("expected /login?error=user_error, got %q", loc)
		}
		if mock.createdUser != nil {
			t.Error("no user should be recorded when CreateUser fails")
		}
	})

	t.Run("missing_email_claim_redirects", func(t *testing.T) {
		idp := newTestIDP(t)
		idToken := idp.mintIDToken(map[string]interface{}{"sub": "no-email-user"})
		idp.setTokenResponse(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		}, http.StatusOK)

		oidcProvider, err := oidc.NewProvider(context.Background(), idp.URL)
		if err != nil {
			t.Fatalf("failed to create OIDC provider: %v", err)
		}

		mock := newMockAPI()
		p := &Plugin{api: mock}
		p.provider = &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     oidcProvider.Endpoint(),
		}
		p.verifier = oidcProvider.Verifier(&oidc.Config{ClientID: "test-client"})

		state := "test-state"
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?state="+state+"&code=valid-code", nil)
		req.AddCookie(&http.Cookie{Name: cookieStateKey, Value: state})
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/login?error=user_error" {
			t.Errorf("expected /login?error=user_error, got %q", loc)
		}
		if mock.createdUser != nil {
			t.Error("no user should be created when the ID token has no email claim")
		}
	})

	t.Run("create_session_failure_redirects", func(t *testing.T) {
		idp := newTestIDP(t)
		idp.setTokenResponse(idp.mintValidTokenResponse(nil), http.StatusOK)

		oidcProvider, err := oidc.NewProvider(context.Background(), idp.URL)
		if err != nil {
			t.Fatalf("failed to create OIDC provider: %v", err)
		}

		mock := newMockAPI()
		// Pre-seed the user so getOrCreateUser succeeds without CreateUser
		mock.usersByEmail["testuser@example.com"] = &model.User{
			Id:       model.NewId(),
			Email:    "testuser@example.com",
			Username: "testuser",
			Roles:    "system_user",
		}
		mock.createSessionErr = model.NewAppError("mock", "mock.create_session_failure", nil, "", http.StatusInternalServerError)
		p := &Plugin{api: mock}
		p.provider = &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     oidcProvider.Endpoint(),
		}
		p.verifier = oidcProvider.Verifier(&oidc.Config{ClientID: "test-client"})

		state := "test-state"
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?state="+state+"&code=valid-code", nil)
		req.AddCookie(&http.Cookie{Name: cookieStateKey, Value: state})
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/login?error=session_error" {
			t.Errorf("expected /login?error=session_error, got %q", loc)
		}
	})

	t.Run("config_error_when_provider_nil_at_callback", func(t *testing.T) {
		mock := newMockAPI()
		p := &Plugin{api: mock}
		// provider is intentionally nil

		state := "test-state"
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/callback?state="+state+"&code=abc", nil)
		req.AddCookie(&http.Cookie{Name: cookieStateKey, Value: state})
		w := httptest.NewRecorder()

		p.handleCallback(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/login?error=config_error" {
			t.Errorf("expected /login?error=config_error, got %q", loc)
		}
	})
}

// --- ServeHTTP routing tests ---

func TestServeHTTP_Routing(t *testing.T) {
	mock := newMockAPI()
	p := &Plugin{api: mock}

	tests := []struct {
		path string
		want int
	}{
		{"/login", http.StatusFound},          // will redirect (provider nil)
		{"/api/public-config", http.StatusOK}, // returns config
		{"/unknown", http.StatusNotFound},     // 404
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			p.ServeHTTP(nil, w, req)
			if w.Code != tc.want {
				t.Errorf("GET %s: expected %d, got %d", tc.path, tc.want, w.Code)
			}
		})
	}
}
