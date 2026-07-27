package validation

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Errors returned by the IP helpers.
var (
	// ErrInvalidIP is returned when a value cannot be parsed as an IP address.
	ErrInvalidIP = errors.New("invalid ip: not a valid address")

	// ErrInvalidCIDR is returned when a value cannot be parsed as a CIDR prefix.
	ErrInvalidCIDR = errors.New("invalid cidr: not a valid prefix")

	// ErrInvalidAddrPort is returned when a value cannot be parsed as an
	// "ip:port" pair.
	ErrInvalidAddrPort = errors.New("invalid address: not a valid ip:port pair")
)

// nonGlobalPrefixes lists the IPv4 and IPv6 ranges that are not globally
// routable on the public internet, per RFC 6890, RFC 5737, RFC 6598,
// RFC 3849, RFC 6666, and RFC 8215.
var nonGlobalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("10.0.0.0/8"),      // private
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local
	netip.MustParsePrefix("172.16.0.0/12"),   // private
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast (deprecated)
	netip.MustParsePrefix("192.168.0.0/16"),  // private
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, incl. broadcast

	netip.MustParsePrefix("::/128"),         // unspecified
	netip.MustParsePrefix("::1/128"),        // loopback
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use translation
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001::/23"),      // IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
	netip.MustParsePrefix("fc00::/7"),       // unique local
	netip.MustParsePrefix("fe80::/10"),      // link-local
	netip.MustParsePrefix("ff00::/8"),       // multicast
}

// ParseIP parses input as an IP address.
//
// Surrounding whitespace is ignored and IPv4-mapped IPv6 addresses such as
// "::ffff:192.0.2.1" are unmapped to their IPv4 form, so callers cannot bypass
// IPv4-based checks by using the mapped notation. IPv6 zones (for example
// "fe80::1%eth0") are preserved. Invalid input is rejected with an error
// wrapping [ErrInvalidIP].
//
// The returned [net/netip.Addr] carries the standard library's own
// classification and formatting methods, so use it directly for everything
// this package does not answer: addr.IsLoopback, addr.IsPrivate,
// addr.IsMulticast, addr.IsLinkLocalUnicast, addr.String, and so on.
func ParseIP(input string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(input))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %q", ErrInvalidIP, input)
	}

	return addr.Unmap(), nil
}

// ParseCIDR parses input as a CIDR prefix such as "10.0.0.0/8" or
// "2001:db8::/32" and returns it in canonical, masked form: host bits outside
// the prefix length are cleared, so "10.1.2.3/8" becomes "10.0.0.0/8".
//
// Invalid input is rejected with an error wrapping [ErrInvalidCIDR].
func ParseCIDR(input string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(input))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %q", ErrInvalidCIDR, input)
	}

	return prefix.Masked(), nil
}

// ParseAddrPort parses input as an "ip:port" pair such as "192.0.2.1:8080" or
// "[2001:db8::1]:8080". The address half is unmapped as described in
// [ParseIP]. Invalid input is rejected with an error wrapping
// [ErrInvalidAddrPort].
func ParseAddrPort(input string) (netip.AddrPort, error) {
	addrPort, err := netip.ParseAddrPort(strings.TrimSpace(input))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %q", ErrInvalidAddrPort, input)
	}

	return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()), nil
}

// IsValidIP reports whether input is a valid IPv4 or IPv6 address.
func IsValidIP(input string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(input))
	return err == nil
}

// IsValidIPv4 reports whether input is a valid IPv4 address. IPv4-mapped IPv6
// addresses such as "::ffff:192.0.2.1" count as IPv4.
func IsValidIPv4(input string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(input))
	return err == nil && addr.Unmap().Is4()
}

// IsValidIPv6 reports whether input is a valid IPv6 address. IPv4-mapped IPv6
// addresses count as IPv4 and therefore report false.
func IsValidIPv6(input string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(input))
	return err == nil && addr.Unmap().Is6()
}

// IsValidCIDR reports whether input is a valid CIDR prefix.
func IsValidCIDR(input string) bool {
	_, err := netip.ParsePrefix(strings.TrimSpace(input))
	return err == nil
}

// IsPublicIP reports whether input is a globally routable unicast address.
//
// It returns false for invalid input and for every special-purpose range,
// including private, loopback, link-local, carrier-grade NAT, documentation,
// benchmarking, multicast, and reserved addresses. Zoned addresses are never
// public because a zone only has meaning on a specific link. This makes
// IsPublicIP a suitable guard against server-side request forgery when
// validating user-supplied destinations.
func IsPublicIP(input string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(input))
	if err != nil || addr.Zone() != "" {
		return false
	}

	unmapped := addr.Unmap()
	for _, prefix := range nonGlobalPrefixes {
		if prefix.Contains(unmapped) {
			return false
		}
	}

	return true
}

// IPInCIDR reports whether ip falls inside at least one of cidrs. An address
// of a different family than a prefix is not contained by it, which is not an
// error, and IPv6 zones are ignored during the comparison.
//
// It returns an error wrapping [ErrInvalidIP] or [ErrInvalidCIDR] if any
// argument is malformed, and false with no error when cidrs is empty.
func IPInCIDR(ip string, cidrs ...string) (bool, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false, fmt.Errorf("%w: %q", ErrInvalidIP, ip)
	}
	addr = addr.Unmap().WithZone("")

	found := false
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return false, fmt.Errorf("%w: %q", ErrInvalidCIDR, cidr)
		}
		if prefix.Contains(addr) {
			found = true
		}
	}

	return found, nil
}
