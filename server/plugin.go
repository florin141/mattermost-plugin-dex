package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"golang.org/x/oauth2"
)

const (
	pluginID              = "com.mattermost.dex"
	cookieSessionTokenKey = "MMAUTHTOKEN"
	cookieStateKey        = "dex_oauth_state"
	stateCookieMaxAge     = 600 // 10 minutes
	sessionTTL            = 30 * 24 * time.Hour
)

// pluginConfig holds the settings from plugin.json.
type pluginConfig struct {
	IssuerURL    string `json:"IssuerURL"`
	ClientID     string `json:"ClientID"`
	ClientSecret string `json:"ClientSecret"`
	ButtonLabel  string `json:"ButtonLabel"`
	ButtonColor  string `json:"ButtonColor"`
	RedirectURL  string `json:"RedirectURL"`
}

// publicConfigResponse is the camelCase DTO returned to the webapp.
type publicConfigResponse struct {
	IssuerURL   string `json:"issuerUrl"`
	ClientID    string `json:"clientId"`
	ButtonLabel string `json:"buttonLabel"`
	ButtonColor string `json:"buttonColor"`
	RedirectURL string `json:"redirectUrl"`
}

// claims holds OIDC ID token claims.
type claims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified"`
	PreferredName string `json:"preferred_username"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
}

// Plugin implements the Mattermost plugin interface and handles Dex OIDC authentication.
type Plugin struct {
	plugin.MattermostPlugin // embedded for API access

	api api // seam for testability; set to p.API in OnActivate

	config pluginConfig

	mu       sync.Mutex
	provider *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// OnConfigurationChange is called when the plugin config changes.
func (p *Plugin) OnConfigurationChange() error {
	if p.api == nil {
		p.api = p.API
	}

	// Load the saved configuration. Zero values are load-bearing: they mark
	// an unconfigured plugin. Do not pre-populate credential placeholders,
	// otherwise an unconfigured plugin would attempt OIDC discovery against
	// a bogus issuer instead of surfacing a config error.
	var cfg pluginConfig
	if err := p.api.LoadPluginConfiguration(&cfg); err != nil {
		return fmt.Errorf("failed to load plugin config: %w", err)
	}

	// Default the cosmetic settings so the public config endpoint stays
	// well-formed when the admin has not customized them.
	if cfg.ButtonLabel == "" {
		cfg.ButtonLabel = "Sign in with Dex"
	}
	if cfg.ButtonColor == "" {
		cfg.ButtonColor = "#009EDB"
	}

	// Auto-detect redirect URL if not set
	if cfg.RedirectURL == "" {
		if siteURL := p.getSiteURL(); siteURL != "" {
			cfg.RedirectURL = fmt.Sprintf("%s/plugins/%s/callback", siteURL, pluginID)
		}
	}

	// The plugin is unconfigured until all OIDC credentials are present;
	// until then p.provider stays nil and /login redirects to
	// /login?error=config_error.
	unconfigured := cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == ""

	// Publish the config under the lock so that p.config, p.provider and
	// p.verifier only ever change while holding p.mu (M-1: no data race vs
	// the lock-protected reads). When unconfigured, clear any stale
	// provider so a previously valid setup does not keep working after the
	// credentials are removed.
	p.mu.Lock()
	prev := p.config
	p.config = cfg
	if unconfigured {
		p.provider = nil
		p.verifier = nil
	}
	p.mu.Unlock()

	if unconfigured {
		// Warn only when the config actually changed, so repeated saves of
		// the same unconfigured settings do not spam the log.
		if prev != cfg {
			p.api.LogWarn("plugin unconfigured - no issuer URL or client credentials set; /login will redirect to config_error")
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		p.api.LogWarn("failed to create OIDC provider", "issuer", cfg.IssuerURL, "error", err.Error())
		return nil
	}

	p.mu.Lock()
	p.provider = &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		Endpoint:     provider.Endpoint(),
	}
	p.verifier = provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})
	p.mu.Unlock()

	p.api.LogInfo("OIDC provider initialized", "issuer", cfg.IssuerURL)

	return nil
}

// OnActivate is called when the plugin is activated.
func (p *Plugin) OnActivate() error {
	if p.api == nil {
		p.api = p.API
	}

	siteURL := p.getSiteURL()
	if siteURL == "" {
		p.api.LogWarn("site URL is empty, plugin will operate with defaults")
	}
	return p.OnConfigurationChange()
}

// getSiteURL returns the Mattermost site URL.
func (p *Plugin) getSiteURL() string {
	cfg := p.api.GetConfig()
	if cfg == nil {
		return ""
	}
	if cfg.ServiceSettings.SiteURL == nil {
		return ""
	}
	return *cfg.ServiceSettings.SiteURL
}

// isHTTPS returns true when the server is configured for HTTPS.
func (p *Plugin) isHTTPS() bool {
	cfg := p.api.GetConfig()
	if cfg == nil {
		return true
	}
	if cfg.ServiceSettings.ConnectionSecurity == nil {
		return true
	}
	return *cfg.ServiceSettings.ConnectionSecurity != "http"
}

// ServeHTTP handles HTTP requests for the plugin's API endpoints.
func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch path {
	case "/login":
		p.handleLogin(w, r)
	case "/api/public-config":
		p.GetPluginPublicConfig(w, r)
	case "/callback":
		p.handleCallback(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleLogin initiates the OAuth flow: generates state, sets the state
// cookie, and redirects to the IdP's authorization endpoint.
func (p *Plugin) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p.mu.Lock()
	conf := p.provider
	p.mu.Unlock()

	if conf == nil {
		http.Redirect(w, r, "/login?error=config_error", http.StatusFound)
		return
	}

	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		p.api.LogError("failed to generate state", "error", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	state := hex.EncodeToString(stateBytes)

	cookie := &http.Cookie{
		Name:     cookieStateKey,
		Value:    state,
		Path:     "/plugins/" + pluginID,
		MaxAge:   stateCookieMaxAge,
		HttpOnly: true,
		Secure:   p.isHTTPS(),
		// Lax (not Strict) so the IdP->/callback cross-site top-level GET still carries the state cookie.
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	authURL := conf.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GetPluginPublicConfig returns the public OIDC configuration for the webapp.
// No secrets are included in the response.
func (p *Plugin) GetPluginPublicConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	p.mu.Lock()
	resp := publicConfigResponse{
		IssuerURL:   p.config.IssuerURL,
		ClientID:    p.config.ClientID,
		ButtonLabel: p.config.ButtonLabel,
		ButtonColor: p.config.ButtonColor,
		RedirectURL: p.config.RedirectURL,
	}
	p.mu.Unlock()

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		p.api.LogError("failed to encode public config response", "error", err.Error())
	}
}

// handleCallback processes the OAuth2 callback from Dex.
func (p *Plugin) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Validate OAuth2 state parameter
	state := r.URL.Query().Get("state")
	if state == "" {
		p.api.LogWarn("callback missing state parameter", "ip", r.RemoteAddr)
		http.Redirect(w, r, "/login?error=invalid_request", http.StatusFound)
		return
	}

	// Verify state matches the stored cookie
	storedState, err := r.Cookie(cookieStateKey)
	if err != nil || subtle.ConstantTimeCompare([]byte(storedState.Value), []byte(state)) != 1 {
		p.api.LogWarn("oauth state mismatch", "ip", r.RemoteAddr)
		http.Redirect(w, r, "/login?error=invalid_state", http.StatusFound)
		return
	}

	// Delete the state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     cookieStateKey,
		Value:    "",
		Path:     "/plugins/" + pluginID,
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Exchange code for tokens
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, "/login?error=no_code", http.StatusFound)
		return
	}

	p.mu.Lock()
	conf := p.provider
	verifier := p.verifier
	p.mu.Unlock()

	if conf == nil {
		http.Redirect(w, r, "/login?error=config_error", http.StatusFound)
		return
	}

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		p.api.LogError("token exchange failed", "error", err.Error())
		http.Redirect(w, r, "/login?error=token_exchange_failed", http.StatusFound)
		return
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		p.api.LogWarn("no id_token in token response", "ip", r.RemoteAddr)
		http.Redirect(w, r, "/login?error=no_id_token", http.StatusFound)
		return
	}

	// Verify the ID token
	if verifier == nil {
		http.Redirect(w, r, "/login?error=config_error", http.StatusFound)
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		p.api.LogError("id token verification failed", "error", err.Error())
		http.Redirect(w, r, "/login?error=invalid_token", http.StatusFound)
		return
	}

	// Parse claims
	var c claims
	if err := idToken.Claims(&c); err != nil {
		p.api.LogError("failed to parse id token claims", "error", err.Error())
		http.Redirect(w, r, "/login?error=invalid_claims", http.StatusFound)
		return
	}

	// Get or create the user
	user, err := p.getOrCreateUser(c)
	if err != nil {
		p.api.LogError("user lookup or creation failed", "error", err.Error())
		http.Redirect(w, r, "/login?error=user_error", http.StatusFound)
		return
	}

	// Create session
	session := &model.Session{
		UserId:         user.Id,
		Roles:          user.Roles,
		IsOAuth:        true,
		LastActivityAt: time.Now().Unix(),
		CreateAt:       time.Now().Unix(),
		ExpiresAt:      time.Now().Add(sessionTTL).Unix(),
	}

	createdSession, appErr := p.api.CreateSession(session)
	if appErr != nil {
		p.api.LogError("session creation failed", "error", appErr.Error())
		http.Redirect(w, r, "/login?error=session_error", http.StatusFound)
		return
	}

	// Set the authentication cookie
	cookie := &http.Cookie{
		Name:     cookieSessionTokenKey,
		Value:    createdSession.Token,
		Path:     "/",
		Domain:   "",
		Expires:  time.Now().Add(sessionTTL),
		HttpOnly: true,
		Secure:   p.isHTTPS(),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// Redirect to the home page
	http.Redirect(w, r, "/", http.StatusFound)
}

// getOrCreateUser finds or creates a user based on OIDC claims.
func (p *Plugin) getOrCreateUser(c claims) (*model.User, error) {
	email := strings.ToLower(strings.TrimSpace(c.Email))
	if email == "" {
		return nil, fmt.Errorf("no email in claims")
	}

	user, appErr := p.api.GetUserByEmail(email)
	if appErr != nil {
		return p.createUser(email, c)
	}

	return user, nil
}

// createUser creates a new Mattermost user from OIDC claims.
func (p *Plugin) createUser(email string, c claims) (*model.User, error) {
	baseUsername := p.generateUsername(c.PreferredName)
	if baseUsername == "" {
		baseUsername = model.NewRandomString(16)
	}

	// Handle username collisions
	var username string
	for i := 0; i < 5; i++ {
		if i > 0 {
			username = fmt.Sprintf("%s%d", baseUsername, i)
		} else {
			username = baseUsername
		}
		_, appErr := p.api.GetUserByUsername(username)
		if appErr != nil {
			break // username is free
		}
	}

	username = p.cleanUsername(username)

	user := &model.User{
		Email:         email,
		EmailVerified: true,
		Nickname:      strings.ToLower(strings.TrimSpace(c.PreferredName)),
		FirstName:     c.GivenName,
		LastName:      c.FamilyName,
		Username:      username,
		AuthService:   "oauth",
		Password:      model.NewRandomString(32),
	}

	created, appErr := p.api.CreateUser(user)
	if appErr != nil {
		return nil, fmt.Errorf("failed to create user: %w", appErr)
	}

	p.api.LogInfo("new user created via Dex SSO", "user_id", created.Id)

	return created, nil
}

// generateUsername creates a username from a preferred name.
func (p *Plugin) generateUsername(preferredName string) string {
	if preferredName == "" {
		return ""
	}

	name := strings.ToLower(preferredName)
	name = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return -1
	}, name)

	// Remove consecutive special characters
	var sb strings.Builder
	var lastSpecial bool
	for _, r := range name {
		if r == '-' || r == '_' {
			if !lastSpecial {
				sb.WriteRune(r)
				lastSpecial = true
			}
		} else {
			sb.WriteRune(r)
			lastSpecial = false
		}
	}
	name = sb.String()

	name = strings.Trim(name, "-_")
	if len(name) < 1 {
		return ""
	}

	return name
}

// cleanUsername ensures the username is valid per Mattermost requirements.
func (p *Plugin) cleanUsername(username string) string {
	if len(username) > 0 {
		first := username[0]
		if (first < 'a' || first > 'z') && (first < 'A' || first > 'Z') {
			username = "u" + username
		}
	}

	if len(username) > 64 {
		username = username[:64]
	}

	return username
}

// OnDeactivate cleans up plugin state when deactivated.
func (p *Plugin) OnDeactivate() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.provider = nil
	p.verifier = nil
	return nil
}

func main() {
	plugin.ClientMain(&Plugin{})
}
