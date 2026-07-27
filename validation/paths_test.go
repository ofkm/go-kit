package validation_test

import (
	"errors"
	"testing"

	"go.ofkm.dev/kit/validation"
)

func TestSanitizePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{name: "empty", input: "", want: "/"},
		{name: "whitespace", input: "   ", want: "/"},
		{name: "root", input: "/", want: "/"},
		{name: "relative", input: "data/logs", want: "/data/logs"},
		{name: "absolute", input: "/data/logs", want: "/data/logs"},
		{name: "trailing slash", input: "/data/logs/", want: "/data/logs"},
		{name: "duplicate slashes", input: "//data///logs", want: "/data/logs"},
		{name: "dot segments", input: "/data/./logs", want: "/data/logs"},
		{name: "surrounding whitespace", input: "  /data/logs  ", want: "/data/logs"},
		{name: "dotfile is allowed", input: "/data/..hidden", want: "/data/..hidden"},

		{name: "parent only", input: "..", wantErr: validation.ErrPathTraversal},
		{name: "parent prefix", input: "../etc/passwd", wantErr: validation.ErrPathTraversal},
		{name: "parent middle", input: "/data/../../etc", wantErr: validation.ErrPathTraversal},
		{name: "parent suffix", input: "/data/..", wantErr: validation.ErrPathTraversal},
		{name: "backslash traversal", input: `..\etc`, wantErr: validation.ErrPathTraversal},
		{name: "nul byte", input: "/data/\x00", wantErr: validation.ErrPathInvalidCharacter},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := validation.SanitizePath(tt.input)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("SanitizePath(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				if got != "" {
					t.Fatalf("SanitizePath(%q) = %q, want empty on error", tt.input, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("SanitizePath(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("SanitizePath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsWithinRoot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		root   string
		target string
		want   bool
	}{
		{name: "same path", root: "/data", target: "/data", want: true},
		{name: "nested", root: "/data", target: "/data/logs/app.log", want: true},
		{name: "root matches all", root: "/", target: "/etc/passwd", want: true},
		{name: "sibling", root: "/data", target: "/database", want: false},
		{name: "outside", root: "/data", target: "/etc", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := validation.IsWithinRoot(tt.root, tt.target)
			if err != nil {
				t.Fatalf("IsWithinRoot(%q, %q) unexpected error: %v", tt.root, tt.target, err)
			}
			if got != tt.want {
				t.Fatalf("IsWithinRoot(%q, %q) = %v, want %v", tt.root, tt.target, got, tt.want)
			}
		})
	}
}

func TestJoinPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		base     string
		elements []string
		want     string
		wantErr  error
	}{
		{name: "simple", base: "/data", elements: []string{"logs", "app.log"}, want: "/data/logs/app.log"},
		{name: "no elements", base: "/data", want: "/data"},
		{name: "clamped dot", base: "/data", elements: []string{"./logs"}, want: "/data/logs"},
		{name: "stays inside", base: "/data", elements: []string{"logs", "..", "cache"}, want: "/data/cache"},

		{name: "escapes base", base: "/data", elements: []string{".."}, wantErr: validation.ErrPathTraversal},
		{name: "escapes base deep", base: "/data", elements: []string{"../../etc"}, wantErr: validation.ErrPathTraversal},
		{name: "nul byte", base: "/data", elements: []string{"\x00"}, wantErr: validation.ErrPathInvalidCharacter},
		{name: "bad base", base: "..", elements: []string{"logs"}, wantErr: validation.ErrPathTraversal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := validation.JoinPath(tt.base, tt.elements...)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("JoinPath(%q, %q) error = %v, want %v", tt.base, tt.elements, err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("JoinPath(%q, %q) unexpected error: %v", tt.base, tt.elements, err)
			}
			if got != tt.want {
				t.Fatalf("JoinPath(%q, %q) = %q, want %q", tt.base, tt.elements, got, tt.want)
			}
		})
	}
}
