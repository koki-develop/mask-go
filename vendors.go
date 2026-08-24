package mask

// This file is the vendor accessors alone. Every vendor whose credentials this
// package reads has one, <Vendor>Patterns, so that a caller reaching for a
// vendor never has to know how many patterns it has nor whether it is one of
// the vendors that has an accessor. A pattern naming a format rather than a
// vendor's credential is in none of them, and JWT is why the rule is worded
// that way.
//
// An accessor is written out as a slice literal rather than derived, because
// what belongs to a vendor is a fact about the vendor and not about any field a
// pattern could carry. Test_vendorAccessors_coverEveryBuiltin
// (vendors_test.go) holds the accessors to naming every built-in between them,
// each of them once, so a pattern added to builtins without joining one fails
// there rather than being reachable only through AllBuiltinPatterns.
//
// Every accessor returns a slice of its own. A caller may sort what it is
// handed, append to it, or hand it straight to WithPatterns, and none of those
// may reach the next caller — which is what AllBuiltinPatterns promises as well
// and what Test_vendorAccessors_freshEachCall holds these to.

// AnthropicPatterns returns every built-in pattern that locates a credential
// Anthropic issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func AnthropicPatterns() []Pattern { return []Pattern{anthropicAPIKey} }

// AWSPatterns returns every built-in pattern that locates a credential AWS
// issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func AWSPatterns() []Pattern { return []Pattern{awsAccessKeyID} }

// GitHubPatterns returns every built-in pattern that locates a credential
// GitHub issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func GitHubPatterns() []Pattern { return []Pattern{githubToken} }

// GitLabPatterns returns every built-in pattern that locates a credential
// GitLab issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func GitLabPatterns() []Pattern { return []Pattern{gitLabToken} }

// GooglePatterns returns every built-in pattern that locates a credential
// Google issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func GooglePatterns() []Pattern { return []Pattern{googleAPIKey} }

// GrafanaPatterns returns every built-in pattern that locates a credential
// Grafana issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func GrafanaPatterns() []Pattern { return []Pattern{grafanaServiceAccountToken} }

// HashiCorpPatterns returns every built-in pattern that locates a credential
// HashiCorp issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func HashiCorpPatterns() []Pattern { return []Pattern{hashiCorpVaultToken} }

// LinearPatterns returns every built-in pattern that locates a credential
// Linear issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func LinearPatterns() []Pattern { return []Pattern{linearAPIKey} }

// NotionPatterns returns every built-in pattern that locates a credential
// Notion issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func NotionPatterns() []Pattern { return []Pattern{notionAPIToken} }

// NPMPatterns returns every built-in pattern that locates a credential npm
// issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func NPMPatterns() []Pattern { return []Pattern{npmAccessToken} }

// OpenAIPatterns returns every built-in pattern that locates a credential
// OpenAI issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func OpenAIPatterns() []Pattern { return []Pattern{openAIAPIKey} }

// OpenRouterPatterns returns every built-in pattern that locates a credential
// OpenRouter issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func OpenRouterPatterns() []Pattern { return []Pattern{openRouterAPIKey} }

// PyPIPatterns returns every built-in pattern that locates a credential PyPI
// issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func PyPIPatterns() []Pattern { return []Pattern{pypiAPIToken} }

// RubyGemsPatterns returns every built-in pattern that locates a credential
// RubyGems issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func RubyGemsPatterns() []Pattern { return []Pattern{rubyGemsAPIKey} }

// SendGridPatterns returns every built-in pattern that locates a credential
// SendGrid issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func SendGridPatterns() []Pattern { return []Pattern{sendGridAPIKey} }

// SentryPatterns returns every built-in pattern that locates a credential
// Sentry issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func SentryPatterns() []Pattern { return []Pattern{sentryAuthToken} }

// SlackPatterns returns every built-in pattern that locates a credential Slack
// issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func SlackPatterns() []Pattern { return []Pattern{slackToken} }

// StripePatterns returns every built-in pattern that locates a credential
// Stripe issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func StripePatterns() []Pattern { return []Pattern{stripePublishableKey, stripeSecretKey} }

// SupabasePatterns returns every built-in pattern that locates a credential
// Supabase issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func SupabasePatterns() []Pattern { return []Pattern{supabaseAccessToken} }
