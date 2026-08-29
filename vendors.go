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

// AirtablePatterns returns every built-in pattern that locates a credential
// Airtable issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func AirtablePatterns() []Pattern { return []Pattern{airtablePersonalAccessToken} }

// AnthropicPatterns returns every built-in pattern that locates a credential
// Anthropic issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func AnthropicPatterns() []Pattern { return []Pattern{anthropicAPIKey} }

// AWSPatterns returns every built-in pattern that locates a credential AWS
// issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func AWSPatterns() []Pattern { return []Pattern{awsAccessKeyID, awsSecretAccessKey} }

// CloudflarePatterns returns every built-in pattern that locates a credential
// Cloudflare issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func CloudflarePatterns() []Pattern { return []Pattern{cloudflareAPIKey, cloudflareAPIToken} }

// CratesIOPatterns returns every built-in pattern that locates a credential
// crates.io issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func CratesIOPatterns() []Pattern { return []Pattern{cratesIOToken} }

// DatabricksPatterns returns every built-in pattern that locates a credential
// Databricks issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func DatabricksPatterns() []Pattern {
	return []Pattern{databricksOAuthClientSecret, databricksPersonalAccessToken}
}

// DigitalOceanPatterns returns every built-in pattern that locates a credential
// DigitalOcean issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func DigitalOceanPatterns() []Pattern { return []Pattern{digitalOceanToken} }

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

// HuggingFacePatterns returns every built-in pattern that locates a credential
// Hugging Face issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func HuggingFacePatterns() []Pattern { return []Pattern{huggingFaceUserAccessToken} }

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

// PlanetScalePatterns returns every built-in pattern that locates a credential
// PlanetScale issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func PlanetScalePatterns() []Pattern { return []Pattern{planetScaleToken} }

// PostmanPatterns returns every built-in pattern that locates a credential
// Postman issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func PostmanPatterns() []Pattern { return []Pattern{postmanAPIKey} }

// PulumiPatterns returns every built-in pattern that locates a credential
// Pulumi issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func PulumiPatterns() []Pattern { return []Pattern{pulumiAccessToken} }

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

// SourcegraphPatterns returns every built-in pattern that locates a credential
// Sourcegraph issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func SourcegraphPatterns() []Pattern { return []Pattern{sourcegraphAccessToken} }

// StripePatterns returns every built-in pattern that locates a credential
// Stripe issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func StripePatterns() []Pattern {
	return []Pattern{stripePublishableKey, stripeSecretKey, stripeWebhookSigningSecret}
}

// SupabasePatterns returns every built-in pattern that locates a credential
// Supabase issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func SupabasePatterns() []Pattern {
	return []Pattern{supabaseAccessToken, supabasePublishableKey, supabaseSecretKey}
}
