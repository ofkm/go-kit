package validation_test

import (
	"errors"
	"testing"

	"go.ofkm.dev/kit/validation"
)

func TestParseIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{name: "ipv4", input: "192.0.2.1", want: "192.0.2.1"},
		{name: "ipv4 surrounding whitespace", input: "  192.0.2.1  ", want: "192.0.2.1"},
		{name: "ipv6 canonicalized", input: "2001:0DB8::0001", want: "2001:db8::1"},
		{name: "ipv6 zone preserved", input: "fe80::1%eth0", want: "fe80::1%eth0"},
		{name: "ipv4 mapped ipv6 is unmapped", input: "::ffff:192.0.2.1", want: "192.0.2.1"},

		{name: "empty", input: "", wantErr: validation.ErrInvalidIP},
		{name: "hostname", input: "example.com", wantErr: validation.ErrInvalidIP},
		{name: "leading zeros", input: "192.000.2.1", wantErr: validation.ErrInvalidIP},
		{name: "out of range octet", input: "192.0.2.256", wantErr: validation.ErrInvalidIP},
		{name: "too few octets", input: "192.0.2", wantErr: validation.ErrInvalidIP},
		{name: "with port", input: "192.0.2.1:80", wantErr: validation.ErrInvalidIP},
		{name: "cidr", input: "192.0.2.0/24", wantErr: validation.ErrInvalidIP},
		{name: "internal whitespace", input: "192.0. 2.1", wantErr: validation.ErrInvalidIP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := validation.ParseIP(tt.input)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseIP(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				if got.IsValid() {
					t.Fatalf("ParseIP(%q) = %v, want zero value on error", tt.input, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseIP(%q) unexpected error: %v", tt.input, err)
			}
			if got.String() != tt.want {
				t.Fatalf("ParseIP(%q) = %q, want %q", tt.input, got.String(), tt.want)
			}
		})
	}
}

func TestParseCIDR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{name: "ipv4", input: "10.0.0.0/8", want: "10.0.0.0/8"},
		{name: "ipv4 host bits masked", input: "10.1.2.3/8", want: "10.0.0.0/8"},
		{name: "ipv4 single host", input: "192.0.2.1/32", want: "192.0.2.1/32"},
		{name: "ipv6", input: "2001:db8::/32", want: "2001:db8::/32"},
		{name: "surrounding whitespace", input: "  10.0.0.0/8  ", want: "10.0.0.0/8"},

		{name: "empty", input: "", wantErr: validation.ErrInvalidCIDR},
		{name: "missing prefix length", input: "10.0.0.0", wantErr: validation.ErrInvalidCIDR},
		{name: "prefix length too large", input: "10.0.0.0/33", wantErr: validation.ErrInvalidCIDR},
		{name: "negative prefix length", input: "10.0.0.0/-1", wantErr: validation.ErrInvalidCIDR},
		{name: "zone not permitted", input: "fe80::1%eth0/64", wantErr: validation.ErrInvalidCIDR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := validation.ParseCIDR(tt.input)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseCIDR(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				if validation.IsValidCIDR(tt.input) {
					t.Fatalf("IsValidCIDR(%q) = true, want false", tt.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseCIDR(%q) unexpected error: %v", tt.input, err)
			}
			if got.String() != tt.want {
				t.Fatalf("ParseCIDR(%q) = %q, want %q", tt.input, got.String(), tt.want)
			}
			if !validation.IsValidCIDR(tt.input) {
				t.Fatalf("IsValidCIDR(%q) = false, want true", tt.input)
			}
		})
	}
}

func TestParseAddrPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{name: "ipv4", input: "192.0.2.1:8080", want: "192.0.2.1:8080"},
		{name: "ipv6", input: "[2001:db8::1]:8080", want: "[2001:db8::1]:8080"},
		{name: "ipv4 mapped ipv6 is unmapped", input: "[::ffff:192.0.2.1]:80", want: "192.0.2.1:80"},
		{name: "surrounding whitespace", input: " 192.0.2.1:80 ", want: "192.0.2.1:80"},

		{name: "empty", input: "", wantErr: validation.ErrInvalidAddrPort},
		{name: "missing port", input: "192.0.2.1", wantErr: validation.ErrInvalidAddrPort},
		{name: "port out of range", input: "192.0.2.1:70000", wantErr: validation.ErrInvalidAddrPort},
		{name: "unbracketed ipv6", input: "2001:db8::1:8080", wantErr: validation.ErrInvalidAddrPort},
		{name: "hostname", input: "example.com:80", wantErr: validation.ErrInvalidAddrPort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := validation.ParseAddrPort(tt.input)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseAddrPort(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseAddrPort(%q) unexpected error: %v", tt.input, err)
			}
			if got.String() != tt.want {
				t.Fatalf("ParseAddrPort(%q) = %q, want %q", tt.input, got.String(), tt.want)
			}
		})
	}
}

func TestIsValidIPFamilies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		wantAny  bool
		wantIPv4 bool
		wantIPv6 bool
	}{
		{name: "ipv4", input: "192.0.2.1", wantAny: true, wantIPv4: true},
		{name: "ipv4 loopback", input: "127.0.0.1", wantAny: true, wantIPv4: true},
		{name: "ipv4 whitespace", input: "  192.0.2.1 ", wantAny: true, wantIPv4: true},
		{name: "ipv6", input: "2001:db8::1", wantAny: true, wantIPv6: true},
		{name: "ipv6 loopback", input: "::1", wantAny: true, wantIPv6: true},
		{name: "ipv6 zone", input: "fe80::1%eth0", wantAny: true, wantIPv6: true},
		{name: "ipv4 mapped ipv6 counts as ipv4", input: "::ffff:192.0.2.1", wantAny: true, wantIPv4: true},
		{name: "hostname", input: "example.com"},
		{name: "empty", input: ""},
		{name: "cidr", input: "10.0.0.0/8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := validation.IsValidIP(tt.input); got != tt.wantAny {
				t.Errorf("IsValidIP(%q) = %v, want %v", tt.input, got, tt.wantAny)
			}
			if got := validation.IsValidIPv4(tt.input); got != tt.wantIPv4 {
				t.Errorf("IsValidIPv4(%q) = %v, want %v", tt.input, got, tt.wantIPv4)
			}
			if got := validation.IsValidIPv6(tt.input); got != tt.wantIPv6 {
				t.Errorf("IsValidIPv6(%q) = %v, want %v", tt.input, got, tt.wantIPv6)
			}
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "public ipv4", input: "8.8.8.8", want: true},
		{name: "public ipv6", input: "2606:4700:4700::1111", want: true},

		{name: "rfc1918 ten", input: "10.1.2.3"},
		{name: "rfc1918 172", input: "172.16.0.1"},
		{name: "rfc1918 192", input: "192.168.1.1"},
		{name: "unique local", input: "fd00::1"},
		{name: "ipv4 loopback", input: "127.0.0.1"},
		{name: "ipv6 loopback", input: "::1"},
		{name: "ipv4 link local", input: "169.254.169.254"},
		{name: "ipv6 link local", input: "fe80::1"},
		{name: "ipv4 multicast", input: "224.0.0.1"},
		{name: "ipv6 multicast", input: "ff02::1"},
		{name: "carrier grade nat", input: "100.64.1.1"},
		{name: "documentation ipv4", input: "192.0.2.1"},
		{name: "documentation ipv6", input: "2001:db8::1"},
		{name: "benchmarking", input: "198.18.0.1"},
		{name: "unspecified ipv4", input: "0.0.0.0"},
		{name: "unspecified ipv6", input: "::"},
		{name: "broadcast", input: "255.255.255.255"},
		{name: "ipv4 mapped private", input: "::ffff:10.1.2.3"},
		{name: "zoned address", input: "fe80::1%eth0"},
		{name: "invalid", input: "nope"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := validation.IsPublicIP(tt.input); got != tt.want {
				t.Fatalf("IsPublicIP(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIPInCIDR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ip      string
		cidrs   []string
		want    bool
		wantErr error
	}{
		{name: "ipv4 inside", ip: "10.1.2.3", cidrs: []string{"10.0.0.0/8"}, want: true},
		{name: "ipv4 outside", ip: "11.1.2.3", cidrs: []string{"10.0.0.0/8"}},
		{name: "ipv4 network address", ip: "10.0.0.0", cidrs: []string{"10.0.0.0/8"}, want: true},
		{name: "unmasked prefix", ip: "10.1.2.3", cidrs: []string{"10.9.9.9/8"}, want: true},
		{name: "ipv4 mapped ipv6 inside", ip: "::ffff:10.1.2.3", cidrs: []string{"10.0.0.0/8"}, want: true},
		{name: "ipv6 inside", ip: "2001:db8::1", cidrs: []string{"2001:db8::/32"}, want: true},
		{name: "ipv6 outside", ip: "2001:db9::1", cidrs: []string{"2001:db8::/32"}},
		{name: "family mismatch", ip: "10.1.2.3", cidrs: []string{"2001:db8::/32"}},
		{name: "zone is ignored", ip: "fe80::1%eth0", cidrs: []string{"fe80::/10"}, want: true},
		{name: "no prefixes", ip: "10.1.2.3"},
		{name: "first of many", ip: "10.9.9.9", cidrs: []string{"10.0.0.0/8", "192.168.0.0/16"}, want: true},
		{name: "last of many", ip: "192.168.1.1", cidrs: []string{"10.0.0.0/8", "192.168.0.0/16"}, want: true},
		{name: "none of many", ip: "8.8.8.8", cidrs: []string{"10.0.0.0/8", "192.168.0.0/16"}},

		{name: "invalid ip", ip: "nope", cidrs: []string{"10.0.0.0/8"}, wantErr: validation.ErrInvalidIP},
		{name: "invalid cidr", ip: "10.1.2.3", cidrs: []string{"10.0.0.0"}, wantErr: validation.ErrInvalidCIDR},
		{name: "invalid cidr after match", ip: "10.1.2.3", cidrs: []string{"10.0.0.0/8", "bogus"}, wantErr: validation.ErrInvalidCIDR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := validation.IPInCIDR(tt.ip, tt.cidrs...)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("IPInCIDR(%q, %v) error = %v, want %v", tt.ip, tt.cidrs, err, tt.wantErr)
				}
				if got {
					t.Fatalf("IPInCIDR(%q, %v) = true, want false on error", tt.ip, tt.cidrs)
				}
				return
			}

			if err != nil {
				t.Fatalf("IPInCIDR(%q, %v) unexpected error: %v", tt.ip, tt.cidrs, err)
			}
			if got != tt.want {
				t.Fatalf("IPInCIDR(%q, %v) = %v, want %v", tt.ip, tt.cidrs, got, tt.want)
			}
		})
	}
}
