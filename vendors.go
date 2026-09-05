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

// AgePatterns returns every built-in pattern that locates a credential age
// generates.
//
// The returned slice is freshly allocated and may be modified by the caller.
func AgePatterns() []Pattern { return []Pattern{ageSecretKey} }

// AirtablePatterns returns every built-in pattern that locates a credential
// Airtable issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func AirtablePatterns() []Pattern { return []Pattern{airtablePersonalAccessToken} }

// AnthropicPatterns returns every built-in pattern that locates a credential
// Anthropic issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func AnthropicPatterns() []Pattern { return []Pattern{anthropicCredential} }

// AWSPatterns returns every built-in pattern that locates a credential AWS
// issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func AWSPatterns() []Pattern { return []Pattern{awsAccessKeyID, awsSecretAccessKey} }

// BuildkitePatterns returns every built-in pattern that locates a credential
// Buildkite issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func BuildkitePatterns() []Pattern { return []Pattern{buildkiteToken} }

// CircleCIPatterns returns every built-in pattern that locates a credential
// CircleCI issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func CircleCIPatterns() []Pattern { return []Pattern{circleCIAPIToken} }

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

// DockerPatterns returns every built-in pattern that locates a credential
// Docker issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func DockerPatterns() []Pattern { return []Pattern{dockerPersonalAccessToken} }

// DopplerPatterns returns every built-in pattern that locates a credential
// Doppler issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func DopplerPatterns() []Pattern { return []Pattern{dopplerAuthToken} }

// DynatracePatterns returns every built-in pattern that locates a credential
// Dynatrace issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func DynatracePatterns() []Pattern { return []Pattern{dynatraceToken} }

// FlyIOPatterns returns every built-in pattern that locates a credential
// Fly.io issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func FlyIOPatterns() []Pattern { return []Pattern{flyIOAccessToken} }

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

// GroqPatterns returns every built-in pattern that locates a credential Groq
// issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func GroqPatterns() []Pattern { return []Pattern{groqAPIKey} }

// HashiCorpPatterns returns every built-in pattern that locates a credential
// HashiCorp issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func HashiCorpPatterns() []Pattern { return []Pattern{hashiCorpVaultToken, hcpTerraformAPIToken} }

// HerokuPatterns returns every built-in pattern that locates a credential
// Heroku issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func HerokuPatterns() []Pattern { return []Pattern{herokuAPIToken} }

// HuggingFacePatterns returns every built-in pattern that locates a credential
// Hugging Face issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func HuggingFacePatterns() []Pattern { return []Pattern{huggingFaceUserAccessToken} }

// LangSmithPatterns returns every built-in pattern that locates a credential
// LangSmith issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func LangSmithPatterns() []Pattern { return []Pattern{langSmithAPIKey} }

// LinearPatterns returns every built-in pattern that locates a credential
// Linear issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func LinearPatterns() []Pattern { return []Pattern{linearAPIKey} }

// MailchimpPatterns returns every built-in pattern that locates a credential
// Mailchimp issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func MailchimpPatterns() []Pattern { return []Pattern{mailchimpAPIKey} }

// MailerSendPatterns returns every built-in pattern that locates a credential
// MailerSend issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func MailerSendPatterns() []Pattern { return []Pattern{mailerSendAPIToken} }

// NeonPatterns returns every built-in pattern that locates a credential Neon
// issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func NeonPatterns() []Pattern { return []Pattern{neonAPIKey} }

// NetlifyPatterns returns every built-in pattern that locates a credential
// Netlify issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func NetlifyPatterns() []Pattern { return []Pattern{netlifyAuthToken} }

// NewRelicPatterns returns every built-in pattern that locates a credential New
// Relic issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func NewRelicPatterns() []Pattern { return []Pattern{newRelicUserKey} }

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

// OnePasswordPatterns returns every built-in pattern that locates a credential
// 1Password issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func OnePasswordPatterns() []Pattern { return []Pattern{onePasswordServiceAccountToken} }

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

// OryPatterns returns every built-in pattern that locates a credential Ory
// issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func OryPatterns() []Pattern { return []Pattern{oryAPIKey} }

// PaddlePatterns returns every built-in pattern that locates a credential
// Paddle issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func PaddlePatterns() []Pattern { return []Pattern{paddleAPIKey} }

// PerplexityPatterns returns every built-in pattern that locates a credential
// Perplexity issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func PerplexityPatterns() []Pattern { return []Pattern{perplexityAPIKey} }

// PineconePatterns returns every built-in pattern that locates a credential
// Pinecone issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func PineconePatterns() []Pattern { return []Pattern{pineconeAPIKey} }

// PlanetScalePatterns returns every built-in pattern that locates a credential
// PlanetScale issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func PlanetScalePatterns() []Pattern { return []Pattern{planetScaleToken} }

// PostHogPatterns returns every built-in pattern that locates a credential
// PostHog issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func PostHogPatterns() []Pattern { return []Pattern{postHogPersonalAPIKey} }

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

// RenderPatterns returns every built-in pattern that locates a credential
// Render issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func RenderPatterns() []Pattern { return []Pattern{renderAPIKey} }

// ReplicatePatterns returns every built-in pattern that locates a credential
// Replicate issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func ReplicatePatterns() []Pattern { return []Pattern{replicateAPIToken} }

// ResendPatterns returns every built-in pattern that locates a credential
// Resend issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func ResendPatterns() []Pattern { return []Pattern{resendAPIKey} }

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

// ShippoPatterns returns every built-in pattern that locates a credential
// Shippo issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func ShippoPatterns() []Pattern { return []Pattern{shippoAPIToken} }

// ShopifyPatterns returns every built-in pattern that locates a credential
// Shopify issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func ShopifyPatterns() []Pattern { return []Pattern{shopifyAccessToken, shopifyAppSecretKey} }

// SlackPatterns returns every built-in pattern that locates a credential Slack
// issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func SlackPatterns() []Pattern { return []Pattern{slackToken} }

// SonarQubePatterns returns every built-in pattern that locates a credential
// SonarQube issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func SonarQubePatterns() []Pattern { return []Pattern{sonarQubeToken} }

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

// XAIPatterns returns every built-in pattern that locates a credential xAI
// issues.
//
// The returned slice is freshly allocated and may be modified by the caller.
func XAIPatterns() []Pattern { return []Pattern{xaiAPIKey} }
