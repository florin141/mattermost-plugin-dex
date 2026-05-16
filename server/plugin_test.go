package main

import (
	"strings"
	"testing"
)

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
