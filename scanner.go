package main

import (
	"bytes"
	"fmt"
	"regexp"
	"sync"
)

type compiledRule struct {
	// Literal rule fields
	original    []byte
	placeholder []byte
	// Regex rule fields
	re      *regexp.Regexp
	isRegex bool
}

// Scanner performs pattern matching for redaction and rehydration.
// It is safe for concurrent use after construction.
type Scanner struct {
	rules    []compiledRule
	mappings sync.Map // placeholder string → original string (for regex rehydration)
}

// NewScanner creates a Scanner from config rules.
// Returns an error if a regex pattern fails to compile.
func NewScanner(rules []Rule) (*Scanner, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for i, r := range rules {
		if len(r.Pattern) > 0 {
			// Regex rule: anchor at start of remaining buffer
			re, err := regexp.Compile(`\A(?:` + r.Pattern + `)`)
			if err != nil {
				return nil, fmt.Errorf("rule %d: invalid regex pattern: %w", i, err)
			}
			compiled = append(compiled, compiledRule{
				re:      re,
				isRegex: true,
			})
		} else {
			compiled = append(compiled, compiledRule{
				original:    []byte(r.Original),
				placeholder: []byte(r.Placeholder),
			})
		}
	}
	return &Scanner{rules: compiled}, nil
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

	// On rehydrate, first apply stored regex mappings as literal replacements.
	if reverse {
		s.mappings.Range(func(key, value any) bool {
			placeholder := []byte(key.(string))
			original := []byte(value.(string))
			for {
				idx := bytes.Index(buf, placeholder)
				if idx < 0 {
					break
				}
				copy(buf[idx:idx+len(placeholder)], original)
				count++
			}
			return true
		})
	}

	i := 0
	for i < len(buf) {
		matched := false
		for _, r := range s.rules {
			if r.isRegex {
				if reverse {
					// Regex rehydration is handled above via stored mappings.
					continue
				}
				// Redact path: try regex match at current position
				m := r.re.Find(buf[i:])
				if m == nil {
					continue
				}
				matchStr := string(m)
				placeholder := generatePlaceholder(matchStr)
				placeholderBytes := []byte(placeholder)
				copy(buf[i:i+len(m)], placeholderBytes)
				s.mappings.Store(placeholder, matchStr)
				i += len(m)
				count++
				matched = true
				break
			}

			// Literal rule
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
