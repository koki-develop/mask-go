package mask

// DefaultPatterns returns every built-in pattern:
//
//	m := mask.New(mask.WithPatterns(mask.DefaultPatterns()...))
//
// The set grows as patterns are added to this package. The returned slice is
// freshly allocated and may be modified by the caller.
func DefaultPatterns() []Pattern {
	panic("not implemented")
}

// GitHubToken locates GitHub credentials that carry a token prefix: personal
// access tokens (ghp_, github_pat_), OAuth app access tokens (gho_), GitHub App
// user and installation access tokens (ghu_, ghs_) and GitHub App refresh
// tokens (ghr_).
//
// Its name is "github-token".
func GitHubToken() Pattern {
	panic("not implemented")
}

// JWT locates JSON Web Tokens, that is a base64url encoded header, payload and
// signature separated by dots. Only tokens whose header decodes to a JSON
// object are redacted.
//
// Its name is "jwt".
func JWT() Pattern {
	panic("not implemented")
}
