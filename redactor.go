package mask

// Match is a sensitive value located by a Pattern.
type Match struct {
	// Pattern is the pattern that located the value.
	Pattern Pattern

	// Value is the text about to be redacted. When a pattern redacts only
	// part of what it matched, Value holds that part rather than the whole
	// match.
	Value string
}

// Redactor produces the text that replaces a located value.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type Redactor interface {
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
// redact must be safe for concurrent use by multiple goroutines.
func NewRedactor(redact func(m Match) string) Redactor {
	panic("not implemented")
}

// Fixed redacts every value to s. Neither the content nor the length of the
// original survives:
//
//	mask.Fixed("[REDACTED]")
func Fixed(s string) Redactor {
	panic("not implemented")
}

// Fill redacts every value to r repeated once per rune of the original, so the
// length of the original survives. A Masker uses Fill('*') unless given another
// redactor.
func Fill(r rune) Redactor {
	panic("not implemented")
}
