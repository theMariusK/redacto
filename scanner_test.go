package main

import (
	"bytes"
	"testing"
)

func TestRedactSingle(t *testing.T) {
	s := NewScanner([]Rule{
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
	s := NewScanner([]Rule{
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
	s := NewScanner([]Rule{
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
	s := NewScanner([]Rule{
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
	s := NewScanner([]Rule{
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
	s := NewScanner([]Rule{
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
	s := NewScanner([]Rule{
		{Original: "secret", Placeholder: "XXXXXX"},
	})

	var buf []byte
	n := s.Redact(buf)
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

func TestRedactNoRules(t *testing.T) {
	s := NewScanner(nil)

	buf := []byte("some content")
	n := s.Redact(buf)
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

func TestRedactAdjacentPatterns(t *testing.T) {
	s := NewScanner([]Rule{
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
	s := NewScanner([]Rule{
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
