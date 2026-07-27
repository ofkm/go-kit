// Package validation provides small, dependency-free helpers for validating
// and normalizing untrusted user input.
package validation

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// Errors returned by the path helpers.
var (
	// ErrPathTraversal is returned when a path attempts to escape the root.
	ErrPathTraversal = errors.New("invalid path: path traversal not allowed")

	// ErrPathNotAbsolute is returned when a path cannot be normalized to an
	// absolute, slash-separated path.
	ErrPathNotAbsolute = errors.New("invalid path: must be absolute")

	// ErrPathInvalidCharacter is returned when a path contains a character that
	// is never valid in a browse path, such as a NUL byte.
	ErrPathInvalidCharacter = errors.New("invalid path: contains invalid character")
)

// SanitizePath normalizes a path within a rooted file browser.
//
// The returned path is always slash-separated, absolute (rooted at "/"), and
// cleaned of "." and ".." segments. Input that would escape the root is
// rejected with an error wrapping [ErrPathTraversal].
//
// Backslashes are treated as separators so Windows-style input such as
// `..\etc` cannot bypass traversal checks. Empty, whitespace-only, or "/"
// input normalizes to "/".
func SanitizePath(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" || trimmed == "/" {
		return "/", nil
	}

	if strings.ContainsRune(trimmed, '\x00') {
		return "", fmt.Errorf("%w: %q", ErrPathInvalidCharacter, input)
	}

	// Normalize Windows-style separators so traversal checks cannot be bypassed.
	normalized := strings.ReplaceAll(trimmed, `\`, "/")

	// Reject traversal in the raw input rather than silently clamping it to the
	// root, so callers can distinguish malicious input from valid paths.
	for segment := range strings.SplitSeq(normalized, "/") {
		if segment == ".." {
			return "", fmt.Errorf("%w: %q", ErrPathTraversal, input)
		}
	}

	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}

	cleaned := path.Clean(normalized)

	if !path.IsAbs(cleaned) {
		return "", fmt.Errorf("%w: %q", ErrPathNotAbsolute, input)
	}

	return cleaned, nil
}

// IsWithinRoot reports whether target, once sanitized, is equal to or nested
// under root. Both arguments are sanitized with [SanitizePath] first.
func IsWithinRoot(root, target string) (bool, error) {
	cleanRoot, err := SanitizePath(root)
	if err != nil {
		return false, err
	}

	cleanTarget, err := SanitizePath(target)
	if err != nil {
		return false, err
	}

	if cleanRoot == "/" || cleanRoot == cleanTarget {
		return true, nil
	}

	return strings.HasPrefix(cleanTarget, cleanRoot+"/"), nil
}

// JoinPath joins elements onto base and sanitizes the result, guaranteeing
// the result never escapes base.
func JoinPath(base string, elements ...string) (string, error) {
	cleanBase, err := SanitizePath(base)
	if err != nil {
		return "", err
	}

	for _, element := range elements {
		if strings.ContainsRune(element, '\x00') {
			return "", fmt.Errorf("%w: %q", ErrPathInvalidCharacter, element)
		}
	}

	parts := make([]string, 0, len(elements)+1)
	parts = append(parts, cleanBase)
	for _, element := range elements {
		parts = append(parts, strings.ReplaceAll(element, `\`, "/"))
	}

	joined := path.Join(parts...)

	within, err := IsWithinRoot(cleanBase, joined)
	if err != nil {
		return "", err
	}
	if !within {
		return "", fmt.Errorf("%w: %q", ErrPathTraversal, path.Join(elements...))
	}

	return SanitizePath(joined)
}
