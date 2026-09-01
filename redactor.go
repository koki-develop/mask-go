package mask

import (
	"strings"
	"unicode/utf8"
)

// Match is a sensitive value located by a Pattern.
type Match struct {
	// Pattern is the pattern that located the value.
	Pattern Pattern

	// Value is the text about to be redacted. When a pattern redacts only
	// part of what it matched, Value holds that part rather than the whole
	// match.
	//
	// It reaches the other way too. Values that overlap are redacted
	// together as one, and the combined text goes to the redactor under the
	// single pattern Masker.Mask attributes it to, so Value can hold more
	// than that pattern located and most of it can be what another pattern
	// found. Masker.Mask states how the attribution is decided.
	Value string
}

// Redactor produces the text that replaces a located value.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type Redactor interface {
	// Redact returns the text written in place of the value m holds. It is
	// written out as it is returned: the length of the original is not kept
	// unless the text returned keeps it, as Fill does and Fixed does not,
	// and returning the empty string splices the text either side of the
	// value together.
	//
	// What m holds is the attribution of a redaction rather than a promise
	// about the whole of it. Match.Value says where that comes from.
	Redact(m Match) string
}

// NewRedactor returns a Redactor that redacts values with redact:
//
//	mask.NewRedactor(func(m mask.Match) string {
//		if m.Pattern.Name() == "jwt" {
//			return "[JWT]"
//		}
//		return "[REDACTED]"
//	})
//
// A redactor reading the name, as this one does, is reading the attribution of
// what it was handed rather than a promise about the whole of it: a JWT written
// against another credential is redacted together with it, and the one label
// then stands for both. Match.Value says where that comes from.
//
// redact must be safe for concurrent use by multiple goroutines.
func NewRedactor(redact func(m Match) string) Redactor {
	return &funcRedactor{redact: redact}
}

type funcRedactor struct {
	redact func(m Match) string
}

func (r *funcRedactor) Redact(m Match) string { return r.redact(m) }

// Fixed redacts every value to s. Neither the content nor the length of the
// original survives:
//
//	mask.Fixed("[REDACTED]")
func Fixed(s string) Redactor {
	return &funcRedactor{redact: func(Match) string { return s }}
}

// Fill redacts every value to r repeated once per rune of the original, so the
// length of the original survives. A Masker uses Fill('*') unless given another
// redactor.
func Fill(r rune) Redactor {
	fill := string(r)
	return &funcRedactor{redact: func(m Match) string {
		return strings.Repeat(fill, utf8.RuneCountInString(m.Value))
	}}
}
