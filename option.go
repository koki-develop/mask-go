package mask

// Option configures a Masker.
type Option func(*options)

type options struct {
	patterns []Pattern
	redactor Redactor
}

// WithPatterns adds patterns for a Masker to scan with. Repeated options
// accumulate in the order given:
//
//	m := mask.New(
//		mask.WithPatterns(mask.GitHubToken(), mask.JWT()),
//		mask.WithPatterns(mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`)),
//	)
func WithPatterns(patterns ...Pattern) Option {
	return func(o *options) { o.patterns = append(o.patterns, patterns...) }
}

// WithRedactor sets what located values are redacted to, replacing Fill('*').
func WithRedactor(r Redactor) Option {
	return func(o *options) { o.redactor = r }
}
