package main

import "bytes"

type compiledRule struct {
	original    []byte
	placeholder []byte
}

// Scanner performs pattern matching for redaction and rehydration.
// It is safe for concurrent use after construction.
type Scanner struct {
	rules []compiledRule
}

// NewScanner creates a Scanner from config rules.
func NewScanner(rules []Rule) *Scanner {
	compiled := make([]compiledRule, len(rules))
	for i, r := range rules {
		compiled[i] = compiledRule{
			original:    []byte(r.Original),
			placeholder: []byte(r.Placeholder),
		}
	}
	return &Scanner{rules: compiled}
}

// Redact replaces all occurrences of original patterns with their placeholders
// in buf, in-place. Returns the number of replacements made.
func (s *Scanner) Redact(buf []byte) int {
	return s.scan(buf, false)
}

// Rehydrate replaces all occurrences of placeholders with their originals
// in buf, in-place. Returns the number of replacements made.
func (s *Scanner) Rehydrate(buf []byte) int {
	return s.scan(buf, true)
}

func (s *Scanner) scan(buf []byte, reverse bool) int {
	count := 0
	i := 0
	for i < len(buf) {
		matched := false
		for _, r := range s.rules {
			var find, replace []byte
			if reverse {
				find = r.placeholder
				replace = r.original
			} else {
				find = r.original
				replace = r.placeholder
			}
			if len(find) == 0 || i+len(find) > len(buf) {
				continue
			}
			if bytes.Equal(buf[i:i+len(find)], find) {
				copy(buf[i:i+len(find)], replace)
				i += len(find)
				count++
				matched = true
				break
			}
		}
		if !matched {
			i++
		}
	}
	return count
}
