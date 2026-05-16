package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

const cookieSessionTokenKey = "MMAUTHTOKEN"

// pluginConfig holds the settings from plugin.json.
type pluginConfig struct {
	IssuerURL    string `json:"IssuerURL"`
	ClientID     string `json:"ClientID"`
	ClientSecret string `json:"ClientSecret"`
	ButtonLabel  string `json:"ButtonLabel"`
	ButtonColor  string `json:"ButtonColor"`
	RedirectURL  string `json:"RedirectURL"`
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

	config pluginConfig

	mu       sync.Mutex
	provider *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// OnConfigurationChange is called when the plugin config changes.
func (p *Plugin) OnConfigurationChange() error {
	p.config = pluginConfig{
		IssuerURL:    "https://dex.example.com",
		ClientID:     "mattermost",
		ClientSecret: "secret",
		ButtonLabel:  "Sign in with Dex",
		ButtonColor:  "#009EDB",
	}

	if err := p.API.LoadPluginConfiguration(&p.config); err != nil {
		return fmt.Errorf("failed to load plugin config: %w", err)
	}

	// Auto-detect redirect URL if not set
	if p.config.RedirectURL == "" {
		siteURL := p.getSiteURL()
		if siteURL != "" {
			p.config.RedirectURL = fmt.Sprintf("%s/plugins/com.example.dex-sso/callback", siteURL)
		}
	}

	// Re-initialize OIDC provider
	if p.config.IssuerURL == "" || p.config.ClientID == "" || p.config.ClientSecret == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, p.config.IssuerURL)
	if err != nil {
		p.API.LogWarn("failed to create OIDC provider", "issuer", p.config.IssuerURL, "error", err.Error())
		return nil
	}

	p.mu.Lock()
	p.provider = &oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		RedirectURL:  p.config.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		Endpoint:     provider.Endpoint(),
	}
	p.verifier = provider.Verifier(&oidc.Config{
		ClientID: p.config.ClientID,
	})
	p.mu.Unlock()

	return nil
}

// OnActivate is called when the plugin is activated.
func (p *Plugin) OnActivate() error {
	siteURL := p.getSiteURL()
	if siteURL == "" {
		p.API.LogWarn("site URL is empty, plugin will operate with defaults")
	}
	return p.OnConfigurationChange()
}

// getSiteURL returns the Mattermost site URL.
func (p *Plugin) getSiteURL() string {
	cfg := p.API.GetConfig()
	if cfg == nil {
		return ""
	}
	if cfg.ServiceSettings.SiteURL == nil {
		return ""
	}
	return *cfg.ServiceSettings.SiteURL
}

// ServeHTTP handles HTTP requests for the plugin's API endpoints.
func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch path {
	case "/api/public-config":
		p.GetPluginPublicConfig(w, r)
	case "/callback":
		p.handleCallback(w, r)
	default:
		http.NotFound(w, r)
	}
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
	resp := map[string]string{
		"IssuerURL":   p.config.IssuerURL,
		"ClientId":    p.config.ClientID,
		"ButtonLabel": p.config.ButtonLabel,
		"ButtonColor": p.config.ButtonColor,
		"RedirectURL": p.config.RedirectURL,
	}
	p.mu.Unlock()

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		p.API.LogError("failed to encode public config response", "error", err.Error())
	}
}

// handleCallback processes the OAuth2 callback from Dex.
func (p *Plugin) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Validate OAuth2 state parameter
	state := r.URL.Query().Get("state")
	if state == "" {
		p.API.LogWarn("callback missing state parameter", "ip", r.RemoteAddr)
		http.Redirect(w, r, "/login?error=invalid_request", http.StatusFound)
		return
	}

	// Verify state matches the stored cookie
	storedState, err := r.Cookie("dex_oauth_state")
	if err != nil || storedState.Value != state {
		p.API.LogWarn("oauth state mismatch", "ip", r.RemoteAddr)
		http.Redirect(w, r, "/login?error=invalid_state", http.StatusFound)
		return
	}

	// Delete the state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "dex_oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	// Exchange code for tokens
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, "/login?error=no_code", http.StatusFound)
		return
	}

	p.mu.Lock()
	conf := p.provider
	p.mu.Unlock()

	if conf == nil {
		http.Redirect(w, r, "/login?error=config_error", http.StatusFound)
		return
	}

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		p.API.LogError("token exchange failed", "error", err.Error())
		http.Redirect(w, r, "/login?error=token_exchange_failed", http.StatusFound)
		return
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		p.API.LogWarn("no id_token in token response", "ip", r.RemoteAddr)
		http.Redirect(w, r, "/login?error=no_id_token", http.StatusFound)
		return
	}

	// Verify the ID token
	p.mu.Lock()
	verifier := p.verifier
	p.mu.Unlock()

	if verifier == nil {
		http.Redirect(w, r, "/login?error=config_error", http.StatusFound)
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		p.API.LogError("id token verification failed", "error", err.Error())
		http.Redirect(w, r, "/login?error=invalid_token", http.StatusFound)
		return
	}

	// Parse claims
	var c claims
	if err := idToken.Claims(&c); err != nil {
		p.API.LogError("failed to parse id token claims", "error", err.Error())
		http.Redirect(w, r, "/login?error=invalid_claims", http.StatusFound)
		return
	}

	// Get or create the user
	user, err := p.getOrCreateUser(c)
	if err != nil {
		p.API.LogError("user lookup or creation failed", "error", err.Error())
		http.Redirect(w, r, "/login?error=user_error", http.StatusFound)
		return
	}

	// Create session
	session := &model.Session{
		UserId:      user.Id,
		Roles:       user.Roles,
		IsOAuth:     true,
		LastActivityAt: time.Now().Unix(),
		CreateAt:     time.Now().Unix(),
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour).Unix(),
	}

	createdSession, appErr := p.API.CreateSession(session)
	if appErr != nil {
		p.API.LogError("session creation failed", "error", appErr.Error())
		http.Redirect(w, r, "/login?error=session_error", http.StatusFound)
		return
	}

	// Set the authentication cookie
	isSecure := true
	if siteCfg := p.API.GetConfig(); siteCfg != nil {
		if siteCfg.ServiceSettings.ConnectionSecurity != nil && *siteCfg.ServiceSettings.ConnectionSecurity == "http" {
			isSecure = false
		}
	}

	cookie := &http.Cookie{
		Name:     cookieSessionTokenKey,
		Value:    createdSession.Token,
		Path:     "/",
		Domain:   "",
		Expires:  time.Now().Add(30 * 24 * time.Hour),
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteStrictMode,
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

	user, appErr := p.API.GetUserByEmail(email)
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

	// Handle username collisions (PLAN.md 2.3)
	var username string
	for i := 0; i < 5; i++ {
		if i > 0 {
			username = fmt.Sprintf("%s%d", baseUsername, i)
		} else {
			username = baseUsername
		}
		_, appErr := p.API.GetUserByUsername(username)
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

	if _, appErr := p.API.CreateUser(user); appErr != nil {
		return nil, fmt.Errorf("failed to create user: %w", appErr)
	}

	p.API.LogInfo("new user created via Dex SSO", "username", user.Username, "email", user.Email)

	return user, nil
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
