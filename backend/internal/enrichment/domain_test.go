package enrichment

import "testing"

func TestNormalizeDomain(t *testing.T) {
	for input, want := range map[string]string{" EXAMPLE.COM. ": "example.com", "bücher.test": "xn--bcher-kva.test", "XN--BCHER-KVA.TEST": "xn--bcher-kva.test"} {
		got, err := NormalizeDomain(input)
		if err != nil || got != want {
			t.Fatalf("%q: %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"", "localhost", "127.0.0.1", "::1", "https://example.com/a", "example.com:53", "a..test", "-a.test", "*.test", "a_.test"} {
		if _, err := NormalizeDomain(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}
