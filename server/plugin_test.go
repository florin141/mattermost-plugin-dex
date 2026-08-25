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

// logEntry records a single plugin log call for test assertions.
type logEntry struct {
	level string
	msg   string
}

type mockAPI struct {
	config           *model.Config
	loadedConfig     *pluginConfig
	usersByEmail     map[string]*model.User
	usersByUsername  map[string]*model.User
	createdUser      *model.User
	createdSession   *model.Session
	createUserErr    *model.AppError
	createSessionErr *model.AppError
	logs             []logEntry
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

func (m *mockAPI) LogInfo(message string, keyValuePairs ...interface{}) {
	m.logs = append(m.logs, logEntry{level: "info", msg: message})
}

func (m *mockAPI) LogWarn(message string, keyValuePairs ...interface{}) {
	m.logs = append(m.logs, logEntry{level: "warn", msg: message})
}

func (m *mockAPI) LogError(message string, keyValuePairs ...interface{}) {
	m.logs = append(m.logs, logEntry{level: "error", msg: message})
}

// countLogs returns how many recorded log entries with the given level have
// a message containing the given substring.
func (m *mockAPI) countLogs(level, substring string) int {
	n := 0
	for _, l := range m.logs {
		if l.level == level && strings.Contains(l.msg, substring) {
			n++
		}
	}
	return n
}

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
		{"aisha.okonkwo", "aisha.okonkwo"},
		{"John.Doe", "john.doe"},
		{"a..b", "a.b"},
		{".a.b.", "a.b"},
		{"-._a", "a"},
		{"...", ""},
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

func TestCreateUser_Username(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		preferredName string
		taken         []string // pre-existing usernames to simulate collisions
		validate      func(t *testing.T, username string)
	}{
		{
			name:          "preferred_username_with_dots_preserved",
			email:         "aisha.okonkwo@example.com",
			preferredName: "aisha.okonkwo",
			validate: func(t *testing.T, username string) {
				if username != "aisha.okonkwo" {
					t.Errorf("username = %q, want %q", username, "aisha.okonkwo")
				}
			},
		},
		{
			name:          "no_preferred_username_uses_email_local_part",
			email:         "aisha.okonkwo@example.com",
			preferredName: "",
			validate: func(t *testing.T, username string) {
				if username != "aisha.okonkwo" {
					t.Errorf("username = %q, want %q", username, "aisha.okonkwo")
				}
			},
		},
		{
			name:          "all_stripped_falls_back_to_random",
			email:         "!!!@example.com",
			preferredName: "...",
			validate: func(t *testing.T, username string) {
				// Preferred name and email local part both strip to nothing,
				// so a 16-char random base is expected (possibly with a "u"
				// prefix added by cleanUsername when it starts with a digit).
				if len(username) < 16 {
					t.Errorf("username = %q, want a 16-char random fallback", username)
				}
			},
		},
		{
			name:          "collision_appends_counter",
			email:         "base@example.com",
			preferredName: "base",
			taken:         []string{"base"},
			validate: func(t *testing.T, username string) {
				if username != "base1" {
					t.Errorf("username = %q, want %q", username, "base1")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := newMockAPI()
			for _, u := range tc.taken {
				mock.usersByUsername[u] = &model.User{Id: model.NewId(), Username: u}
			}
			p := &Plugin{api: mock}

			user, err := p.createUser(tc.email, claims{Email: tc.email, PreferredName: tc.preferredName})
			if err != nil {
				t.Fatalf("createUser failed: %v", err)
			}
			tc.validate(t, user.Username)
		})
	}
}

func TestIsHTTPS(t *testing.T) {
	tests := []struct {
		name string
		cfg  *model.Config
		want bool
	}{
		{"nil config fails secure", nil, true},
		{"nil connection security is plain http", configWithConnectionSecurity(nil), false},
		{"empty connection security is plain http", configWithConnectionSecurity(model.NewPointer("")), false},
		{"http is plain http", configWithConnectionSecurity(model.NewPointer("http")), false},
		{"tls is https", configWithConnectionSecurity(model.NewPointer("tls")), true},
		{"strict is https", configWithConnectionSecurity(model.NewPointer("strict")), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := newMockAPI()
			mock.config = tc.cfg
			p := &Plugin{api: mock}
			if got := p.isHTTPS(); got != tc.want {
				t.Errorf("isHTTPS() = %v, want %v", got, tc.want)
			}
		})
	}
}

func configWithConnectionSecurity(cs *string) *model.Config {
	return &model.Config{
		ServiceSettings: model.ServiceSettings{
			SiteURL:            model.NewPointer("http://localhost:8065"),
			ConnectionSecurity: cs,
		},
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

func TestOnConfigurationChange_Unconfigured(t *testing.T) {
	t.Run("no_credentials_provider_stays_nil", func(t *testing.T) {
		mock := newMockAPI()
		// loadedConfig is nil: the admin has not saved any settings
		p := &Plugin{api: mock}
		if err := p.OnConfigurationChange(); err != nil {
			t.Fatalf("OnConfigurationChange failed: %v", err)
		}

		if p.provider != nil {
			t.Error("expected provider to be nil when unconfigured")
		}
		if p.verifier != nil {
			t.Error("expected verifier to be nil when unconfigured")
		}

		// Auto-fill of RedirectURL must still happen
		if p.config.RedirectURL != "http://localhost:8065/plugins/com.mattermost.dex/callback" {
			t.Errorf("RedirectURL = %q, want auto-filled value", p.config.RedirectURL)
		}

		// /login must surface the unconfigured state
		req := httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/login", nil)
		w := httptest.NewRecorder()
		p.handleLogin(w, req)
		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "/login?error=config_error" {
			t.Errorf("expected /login?error=config_error, got %q", loc)
		}

		// Public config must stay well-formed with the default button label
		req = httptest.NewRequest(http.MethodGet, "/plugins/com.mattermost.dex/api/public-config", nil)
		w = httptest.NewRecorder()
		p.GetPluginPublicConfig(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp publicConfigResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.ButtonLabel != "Sign in with Dex" {
			t.Errorf("buttonLabel = %q, want default %q", resp.ButtonLabel, "Sign in with Dex")
		}
		if resp.IssuerURL != "" || resp.ClientID != "" {
			t.Errorf("expected empty issuerUrl/clientId when unconfigured, got %q/%q", resp.IssuerURL, resp.ClientID)
		}

		// The unconfigured state is warned about exactly once...
		if n := mock.countLogs("warn", "unconfigured"); n != 1 {
			t.Errorf("expected exactly 1 unconfigured warning, got %d", n)
		}

		// ...and a repeated identical save must not re-log it
		if err := p.OnConfigurationChange(); err != nil {
			t.Fatalf("second OnConfigurationChange failed: %v", err)
		}
		if n := mock.countLogs("warn", "unconfigured"); n != 1 {
			t.Errorf("expected still 1 unconfigured warning after identical re-save, got %d", n)
		}
	})

	t.Run("partial_credentials_provider_stays_nil", func(t *testing.T) {
		mock := newMockAPI()
		mock.loadedConfig = &pluginConfig{
			IssuerURL: "https://dex.example.com",
			ClientID:  "mattermost",
			// ClientSecret intentionally missing
		}
		p := &Plugin{api: mock}
		if err := p.OnConfigurationChange(); err != nil {
			t.Fatalf("OnConfigurationChange failed: %v", err)
		}
		if p.provider != nil {
			t.Error("expected provider to be nil when client secret is missing")
		}
	})

	t.Run("stale_provider_cleared_when_credentials_removed", func(t *testing.T) {
		idp := newTestIDP(t)
		mock := newMockAPI()
		mock.loadedConfig = &pluginConfig{
			IssuerURL:    idp.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		}
		p := &Plugin{api: mock}
		if err := p.OnConfigurationChange(); err != nil {
			t.Fatalf("first OnConfigurationChange failed: %v", err)
		}
		if p.provider == nil {
			t.Fatal("expected provider to be initialized for a valid issuer")
		}

		// The admin removes the client secret
		mock.loadedConfig = &pluginConfig{
			IssuerURL: idp.URL,
			ClientID:  "test-client",
		}
		if err := p.OnConfigurationChange(); err != nil {
			t.Fatalf("second OnConfigurationChange failed: %v", err)
		}
		if p.provider != nil {
			t.Error("expected stale provider to be cleared when credentials are removed")
		}
		if p.verifier != nil {
			t.Error("expected verifier to be cleared when credentials are removed")
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
		if !mock.createdSession.IsOAuth {
			t.Error("expected IsOAuth=true on created session")
		}
		// The server owns the time fields: the plugin must not set them
		// (seconds vs milliseconds would mark the session expired at creation).
		if mock.createdSession.CreateAt != 0 {
			t.Errorf("session.CreateAt = %d, want 0 (server owns the field)", mock.createdSession.CreateAt)
		}
		if mock.createdSession.LastActivityAt != 0 {
			t.Errorf("session.LastActivityAt = %d, want 0 (server owns the field)", mock.createdSession.LastActivityAt)
		}
		if mock.createdSession.ExpiresAt != 0 {
			t.Errorf("session.ExpiresAt = %d, want 0 (server owns the field)", mock.createdSession.ExpiresAt)
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

		// Verify the companion session cookies the webapp relies on to render a
		// logged-in UI (MMUSERID + MMCSRF). Omitting them leaves the browser on
		// /login even though the API accepts the session. Both must NOT be
		// HttpOnly, since the webapp reads them from document.cookie.
		var userCookie, csrfCookie *http.Cookie
		for _, c := range cookies {
			switch c.Name {
			case model.SessionCookieUser:
				userCookie = c
			case model.SessionCookieCsrf:
				csrfCookie = c
			}
		}
		if userCookie == nil {
			t.Fatal("expected MMUSERID cookie to be set")
		}
		if userCookie.Value != mock.createdSession.UserId {
			t.Errorf("MMUSERID value = %q, want %q", userCookie.Value, mock.createdSession.UserId)
		}
		if userCookie.HttpOnly {
			t.Error("MMUSERID cookie should NOT be HttpOnly (webapp reads it)")
		}
		if csrfCookie == nil {
			t.Fatal("expected MMCSRF cookie to be set")
		}
		if csrfCookie.Value == "" {
			t.Error("MMCSRF value should be non-empty")
		}
		if csrfCookie.Value != mock.createdSession.GetCSRF() {
			t.Errorf("MMCSRF value = %q, want %q", csrfCookie.Value, mock.createdSession.GetCSRF())
		}
		if csrfCookie.HttpOnly {
			t.Error("MMCSRF cookie should NOT be HttpOnly (webapp reads it)")
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
		if !mock.createdSession.IsOAuth {
			t.Error("expected IsOAuth=true on created session")
		}
		if mock.createdSession.CreateAt != 0 || mock.createdSession.LastActivityAt != 0 || mock.createdSession.ExpiresAt != 0 {
			t.Errorf("session time fields must be left to the server, got CreateAt=%d LastActivityAt=%d ExpiresAt=%d",
				mock.createdSession.CreateAt, mock.createdSession.LastActivityAt, mock.createdSession.ExpiresAt)
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

		cookies := w.Result().Cookies()
		for _, name := range []string{cookieSessionTokenKey, model.SessionCookieUser, model.SessionCookieCsrf} {
			var c *http.Cookie
			for _, cc := range cookies {
				if cc.Name == name {
					c = cc
				}
			}
			if c == nil {
				t.Errorf("expected %s cookie to be set", name)
				continue
			}
			if c.Secure {
				t.Errorf("%s cookie should not be Secure on plain HTTP", name)
			}
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
