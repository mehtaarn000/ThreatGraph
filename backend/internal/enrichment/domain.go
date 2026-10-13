package enrichment

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
)

func NormalizeDomain(value string) (string, error) {
	value = strings.TrimSpace(value)
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", ErrInvalidDomain
	}
	ascii = strings.TrimSuffix(strings.ToLower(ascii), ".")
	if len(ascii) > 253 || net.ParseIP(ascii) != nil || !strings.Contains(ascii, ".") {
		return "", ErrInvalidDomain
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidDomain
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", ErrInvalidDomain
			}
		}
	}
	return ascii, nil
}
