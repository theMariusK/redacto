package main

import (
	"bytes"
	"testing"
)

func mustNewScanner(t *testing.T, rules []Rule) *Scanner {
	t.Helper()
	s, err := NewScanner(rules)
	if err != nil {
		t.Fatalf("NewScanner failed: %v", err)
	}
	return s
}

func TestRedactSingle(t *testing.T) {
	s := mustNewScanner(t, []Rule{
		{Original: "secret123", Placeholder: "XXXXXXXXX"},
	})

	buf := []byte("my secret123 value")
	n := s.Redact(buf)

	if n != 1 {
		t.Errorf("expected 1 replacement, got %d", n)
	}
	if string(buf) != "my XXXXXXXXX value" {
		t.Errorf("unexpected result: %q", string(buf))
	}
}

func TestRehydrateSingle(t *testing.T) {
	s := mustNewScanner(t, []Rule{
		{Original: "secret123", Placeholder: "XXXXXXXXX"},
	})

	buf := []byte("my XXXXXXXXX value")
	n := s.Rehydrate(buf)

	if n != 1 {
		t.Errorf("expected 1 replacement, got %d", n)
	}
	if string(buf) != "my secret123 value" {
		t.Errorf("unexpected result: %q", string(buf))
	}
}

func TestRedactMultipleRules(t *testing.T) {
	s := mustNewScanner(t, []Rule{
		{Original: "password", Placeholder: "********"},
		{Original: "apikey12", Placeholder: "KKKKKKKK"},
	})

	buf := []byte("pass=password key=apikey12")
	n := s.Redact(buf)

	if n != 2 {
		t.Errorf("expected 2 replacements, got %d", n)
	}
	if string(buf) != "pass=******** key=KKKKKKKK" {
		t.Errorf("unexpected result: %q", string(buf))
	}
}

func TestRedactMultipleOccurrences(t *testing.T) {
	s := mustNewScanner(t, []Rule{
		{Original: "abc", Placeholder: "XYZ"},
	})

	buf := []byte("abc and abc and abc")
	n := s.Redact(buf)

	if n != 3 {
		t.Errorf("expected 3 replacements, got %d", n)
	}
	if string(buf) != "XYZ and XYZ and XYZ" {
		t.Errorf("unexpected result: %q", string(buf))
	}
}

func TestRedactNoMatch(t *testing.T) {
	s := mustNewScanner(t, []Rule{
		{Original: "missing", Placeholder: "XXXXXXX"},
	})

	buf := []byte("nothing here")
	orig := make([]byte, len(buf))
	copy(orig, buf)

	n := s.Redact(buf)
	if n != 0 {
		t.Errorf("expected 0 replacements, got %d", n)
	}
	if !bytes.Equal(buf, orig) {
		t.Errorf("buffer was modified: %q", string(buf))
	}
}

func TestRoundTrip(t *testing.T) {
	s := mustNewScanner(t, []Rule{
		{Original: "sk-ant-api03-realkey1234567890abcdef", Placeholder: "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXX"},
		{Original: "password1234", Placeholder: "************"},
	})

	original := []byte("key=sk-ant-api03-realkey1234567890abcdef pass=password1234 end")
	buf := make([]byte, len(original))
	copy(buf, original)

	s.Redact(buf)
	if bytes.Equal(buf, original) {
		t.Fatal("redact did not modify buffer")
	}

	s.Rehydrate(buf)
	if !bytes.Equal(buf, original) {
		t.Errorf("round-trip failed: got %q, want %q", string(buf), string(original))
	}
}

func TestRedactEmptyBuffer(t *testing.T) {
	s := mustNewScanner(t, []Rule{
		{Original: "secret", Placeholder: "XXXXXX"},
	})

	var buf []byte
	n := s.Redact(buf)
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

func TestRedactNoRules(t *testing.T) {
	s := mustNewScanner(t, nil)

	buf := []byte("some content")
	n := s.Redact(buf)
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

func TestRedactAdjacentPatterns(t *testing.T) {
	s := mustNewScanner(t, []Rule{
		{Original: "aaa", Placeholder: "XXX"},
	})

	buf := []byte("aaaaaa")
	n := s.Redact(buf)

	if n != 2 {
		t.Errorf("expected 2 replacements, got %d", n)
	}
	if string(buf) != "XXXXXX" {
		t.Errorf("unexpected result: %q", string(buf))
	}
}

func TestRedactOverlappingPrefixNotMatched(t *testing.T) {
	s := mustNewScanner(t, []Rule{
		{Original: "abcd", Placeholder: "XXXX"},
	})

	// "abc" at end — too short to match
	buf := []byte("xabc")
	n := s.Redact(buf)
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

func TestGeneratePlaceholder(t *testing.T) {
	p := generatePlaceholder("hello")
	if len(p) != len("hello") {
		t.Errorf("expected length %d, got %d", len("hello"), len(p))
	}

	// Deterministic
	p2 := generatePlaceholder("hello")
	if p != p2 {
		t.Errorf("not deterministic: %q vs %q", p, p2)
	}

	// Different input → different output
	p3 := generatePlaceholder("world")
	if p == p3 {
		t.Errorf("different inputs produced same placeholder")
	}
}

func TestGeneratePlaceholderLong(t *testing.T) {
	// Test with a string longer than 64 chars (SHA-256 hex is 64 chars)
	long := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	p := generatePlaceholder(long)
	if len(p) != len(long) {
		t.Errorf("expected length %d, got %d", len(long), len(p))
	}
}

// --- Regex rule tests ---

func TestRegexRedactSingle(t *testing.T) {
	// Match exactly 8 hex chars
	s := mustNewScanner(t, []Rule{
		{Pattern: "[0-9a-f]{8}"},
	})

	buf := []byte("token=deadbeef end")
	n := s.Redact(buf)

	if n != 1 {
		t.Errorf("expected 1 replacement, got %d", n)
	}
	// Placeholder is same length as match
	if len(buf) != len("token=deadbeef end") {
		t.Errorf("buffer length changed")
	}
	// The matched portion should be replaced (not "deadbeef" anymore)
	if string(buf[6:14]) == "deadbeef" {
		t.Errorf("match was not replaced")
	}
}

func TestRegexRedactMultipleMatches(t *testing.T) {
	// Match 4-char hex tokens
	s := mustNewScanner(t, []Rule{
		{Pattern: "[0-9a-f]{4}"},
	})

	buf := []byte("a=abcd b=ef01 c=zzzz")
	n := s.Redact(buf)

	// "abcd" at pos 2 and "ef01" at pos 9 should match; "zzzz" has z which is not hex
	if n != 2 {
		t.Errorf("expected 2 replacements, got %d", n)
	}
	if string(buf[2:6]) == "abcd" {
		t.Errorf("first match was not replaced")
	}
	if string(buf[9:13]) == "ef01" {
		t.Errorf("second match was not replaced")
	}
	// "zzzz" should be untouched
	if string(buf[16:20]) != "zzzz" {
		t.Errorf("non-matching text was modified: %q", string(buf[16:20]))
	}
}

func TestRegexRedactNoMatch(t *testing.T) {
	s := mustNewScanner(t, []Rule{
		{Pattern: "[0-9]{10}"},
	})

	buf := []byte("no digits here")
	orig := make([]byte, len(buf))
	copy(orig, buf)

	n := s.Redact(buf)
	if n != 0 {
		t.Errorf("expected 0 replacements, got %d", n)
	}
	if !bytes.Equal(buf, orig) {
		t.Errorf("buffer was modified")
	}
}

func TestRegexRoundTrip(t *testing.T) {
	s := mustNewScanner(t, []Rule{
		{Pattern: "[0-9a-f]{8}"},
	})

	original := []byte("key=deadbeef val=cafebabe end")
	buf := make([]byte, len(original))
	copy(buf, original)

	n := s.Redact(buf)
	if n != 2 {
		t.Errorf("expected 2 redactions, got %d", n)
	}
	if bytes.Equal(buf, original) {
		t.Fatal("redact did not modify buffer")
	}

	n = s.Rehydrate(buf)
	if n != 2 {
		t.Errorf("expected 2 rehydrations, got %d", n)
	}
	if !bytes.Equal(buf, original) {
		t.Errorf("round-trip failed: got %q, want %q", string(buf), string(original))
	}
}

func TestRegexMixedWithLiteral(t *testing.T) {
	s := mustNewScanner(t, []Rule{
		{Original: "password", Placeholder: "********"},
		{Pattern: "[0-9a-f]{8}"},
	})

	original := []byte("pass=password token=deadbeef end")
	buf := make([]byte, len(original))
	copy(buf, original)

	n := s.Redact(buf)
	if n != 2 {
		t.Errorf("expected 2 replacements, got %d", n)
	}
	// Literal replacement
	if string(buf[5:13]) != "********" {
		t.Errorf("literal rule not applied: %q", string(buf[5:13]))
	}
	// Regex replacement (should not be "deadbeef")
	if string(buf[20:28]) == "deadbeef" {
		t.Errorf("regex rule not applied")
	}

	// Round-trip
	s.Rehydrate(buf)
	if !bytes.Equal(buf, original) {
		t.Errorf("round-trip failed: got %q, want %q", string(buf), string(original))
	}
}

func TestNewScannerInvalidRegex(t *testing.T) {
	_, err := NewScanner([]Rule{
		{Pattern: "[invalid"},
	})
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

func TestRegexDeterministicPlaceholder(t *testing.T) {
	// Same match text should produce the same placeholder
	s := mustNewScanner(t, []Rule{
		{Pattern: "[0-9a-f]{4}"},
	})

	buf1 := []byte("abcd")
	buf2 := []byte("abcd")
	s.Redact(buf1)
	s.Redact(buf2)

	if !bytes.Equal(buf1, buf2) {
		t.Errorf("same input produced different placeholders: %q vs %q", buf1, buf2)
	}
}
