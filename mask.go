// Package mask redacts sensitive values such as API keys and access tokens
// from text.
//
// A Masker scans its input with the patterns it was given and redacts every
// value it locates:
//
//	m := mask.New(mask.WithPatterns(mask.DefaultPatterns()...))
//	fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
//
// Output:
//
//	GITHUB_TOKEN=****************************************
//
// A Masker scans only with the patterns given to it; nothing is enabled
// implicitly. DefaultPatterns returns the built-in ones, and a custom pattern
// comes from NewPattern, MustRegexp or any implementation of the Pattern
// interface.
package mask

// Masker redacts sensitive values in text.
//
// A Masker is fixed once created and is safe for concurrent use by multiple
// goroutines.
type Masker struct{}

// New returns a Masker that scans with the patterns given to WithPatterns and
// redacts what it locates with the redactor given to WithRedactor, which
// defaults to Fill('*').
//
// A Masker with no patterns redacts nothing.
func New(opts ...Option) *Masker {
	panic("not implemented")
}

// Mask returns src with every located value redacted.
//
// Where two located values overlap, the longer one is redacted. Where they
// cover the same range, the value located by the pattern added first by
// WithPatterns is redacted.
func (m *Masker) Mask(src string) string {
	panic("not implemented")
}
