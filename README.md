# mask-go

[![GitHub Release](https://img.shields.io/github/v/release/koki-develop/mask-go?style=flat-square)](https://github.com/koki-develop/mask-go/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/koki-develop/mask-go.svg)](https://pkg.go.dev/github.com/koki-develop/mask-go)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/koki-develop/mask-go/ci.yml?style=flat-square&logo=github)](https://github.com/koki-develop/mask-go/actions/workflows/ci.yml)
[![GitHub License](https://img.shields.io/github/license/koki-develop/mask-go?style=flat-square)](./LICENSE)

A Go library for redacting API keys, access tokens and other credentials from
text, with zero dependencies.

## Installation

```sh
go get github.com/koki-develop/mask-go
```

## Usage

```go
m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))

fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
// GITHUB_TOKEN=****************************************
```

A `Masker` scans only with the patterns it is given. Every vendor also has an
accessor of its own, for a caller who wants some of them and not all:

```go
m := mask.New(mask.WithPatterns(slices.Concat(
	mask.AWSPatterns(),
	mask.GitHubPatterns(),
)...))
```

## Built-in patterns

The 69 built-in patterns cover 58 vendors and locate 170 kinds of credential:

| Accessor | Locates |
| --- | --- |
| `AgePatterns() []Pattern` | age X25519 secret keys, age post-quantum hybrid ML-KEM-768 + X25519 secret keys |
| `AirtablePatterns() []Pattern` | Airtable personal access tokens |
| `AnthropicPatterns() []Pattern` | Anthropic API keys, Anthropic Admin API keys, Anthropic OAuth tokens, Anthropic session keys |
| `AWSPatterns() []Pattern` | AWS access key IDs, AWS secret access keys |
| `BuildkitePatterns() []Pattern` | Buildkite API access tokens, agent session tokens, agent job tokens, unclustered agent tokens, agent tokens, registry tokens, Package Registries temporary tokens, portal tokens, portal secrets, job acquisition tokens, token exchange tokens |
| `CircleCIPatterns() []Pattern` | CircleCI personal API tokens, project API tokens |
| `CloudflarePatterns() []Pattern` | Cloudflare API tokens, Cloudflare API keys |
| `CratesIOPatterns() []Pattern` | crates.io API tokens, Trusted Publishing access tokens |
| `DatabricksPatterns() []Pattern` | Databricks personal access tokens, Databricks OAuth client secrets |
| `DigitalOceanPatterns() []Pattern` | DigitalOcean personal access tokens, OAuth access tokens, OAuth refresh tokens |
| `DockerPatterns() []Pattern` | Docker personal access tokens |
| `DopplerPatterns() []Pattern` | Doppler CLI tokens, personal tokens, service tokens, service account tokens, service account identity tokens, SCIM tokens, audit tokens |
| `DynatracePatterns() []Pattern` | Dynatrace access tokens classic, Dynatrace personal access tokens, Dynatrace OAuth2 refresh tokens, Dynatrace platform tokens |
| `FlyIOPatterns() []Pattern` | Fly.io access tokens, Fly.io v1 permission tokens, Fly.io v1 discharge tokens |
| `GitHubPatterns() []Pattern` | GitHub personal access tokens (classic), GitHub fine-grained personal access tokens, GitHub OAuth app access tokens, GitHub App user access tokens, GitHub App installation access tokens, GitHub App refresh tokens |
| `GitLabPatterns() []Pattern` | GitLab personal access tokens, project access tokens, group access tokens, impersonation tokens, OAuth application secrets, deploy tokens, runner authentication tokens, CI/CD job tokens, pipeline trigger tokens, feed tokens, incoming mail tokens, GitLab agent for Kubernetes tokens, SCIM OAuth tokens, feature flags client tokens |
| `GooglePatterns() []Pattern` | Google API keys |
| `GrafanaPatterns() []Pattern` | Grafana service account tokens |
| `GroqPatterns() []Pattern` | Groq API keys |
| `HashiCorpPatterns() []Pattern` | HashiCorp Vault service tokens, batch tokens, recovery tokens, HCP Terraform API tokens |
| `HerokuPatterns() []Pattern` | Heroku API tokens |
| `HuggingFacePatterns() []Pattern` | Hugging Face user access tokens |
| `JWT() Pattern` | signed JSON Web Tokens, encrypted JSON Web Tokens |
| `LangSmithPatterns() []Pattern` | LangSmith personal access tokens, service keys |
| `LinearPatterns() []Pattern` | Linear personal API keys |
| `MailchimpPatterns() []Pattern` | Mailchimp API keys |
| `MailerSendPatterns() []Pattern` | MailerSend API tokens |
| `NeonPatterns() []Pattern` | Neon personal API keys, organization API keys, project-scoped API keys |
| `NetlifyPatterns() []Pattern` | Netlify personal access tokens, Netlify CLI tokens, OAuth access tokens, app.netlify.com tokens, build tokens |
| `NewRelicPatterns() []Pattern` | New Relic user keys |
| `NotionPatterns() []Pattern` | Notion internal connection tokens, Notion OAuth access tokens, Notion personal access tokens |
| `NPMPatterns() []Pattern` | npm granular access tokens, npm legacy read-only tokens, npm legacy automation tokens, npm legacy publish tokens |
| `OnePasswordPatterns() []Pattern` | 1Password service account tokens |
| `OpenAIPatterns() []Pattern` | OpenAI project API keys, service account keys, Admin API keys, legacy user API keys |
| `OpenRouterPatterns() []Pattern` | OpenRouter API keys |
| `OryPatterns() []Pattern` | Ory Network project API keys, workspace API keys |
| `PaddlePatterns() []Pattern` | Paddle API keys |
| `PerplexityPatterns() []Pattern` | Perplexity API keys |
| `PineconePatterns() []Pattern` | Pinecone API keys |
| `PlanetScalePatterns() []Pattern` | PlanetScale service tokens, OAuth access tokens, OAuth refresh tokens |
| `PostHogPatterns() []Pattern` | PostHog personal API keys |
| `PostmanPatterns() []Pattern` | Postman API keys |
| `PrivateKey() Pattern` | PKCS#8 private keys, encrypted PKCS#8 private keys, PKCS#1 RSA private keys, EC private keys, DSA private keys, OpenSSH private keys, PGP private key blocks |
| `PulumiPatterns() []Pattern` | Pulumi personal access tokens, organization access tokens, team access tokens |
| `PyPIPatterns() []Pattern` | PyPI API tokens, TestPyPI API tokens, Trusted Publishing short-lived API tokens |
| `RenderPatterns() []Pattern` | Render API keys |
| `ReplicatePatterns() []Pattern` | Replicate API tokens |
| `ResendPatterns() []Pattern` | Resend API keys |
| `RubyGemsPatterns() []Pattern` | RubyGems.org API keys |
| `SendGridPatterns() []Pattern` | Twilio SendGrid API keys |
| `SentryPatterns() []Pattern` | Sentry personal tokens, organization auth tokens, user application tokens, internal integration tokens |
| `ShippoPatterns() []Pattern` | Shippo live API tokens, test API tokens |
| `ShopifyPatterns() []Pattern` | Shopify public app access tokens, Shopify custom app access tokens, Shopify private app access tokens, Shopify delegate access tokens, Shopify app secret keys |
| `SlackPatterns() []Pattern` | Slack bot tokens, user tokens, app-level tokens, workflow tokens, refresh tokens, expiring access tokens |
| `SonarQubePatterns() []Pattern` | SonarQube user tokens, global analysis tokens, project analysis tokens, project badge tokens |
| `SourcegraphPatterns() []Pattern` | Sourcegraph access tokens |
| `StripePatterns() []Pattern` | Stripe publishable API keys, restricted API keys, secret API keys, organization API keys, webhook signing secrets |
| `SupabasePatterns() []Pattern` | Supabase personal access tokens, Supabase OAuth access tokens, Supabase publishable API keys, Supabase secret API keys |
| `TailscalePatterns() []Pattern` | Tailscale API access tokens, auth keys, OAuth client keys, SCIM keys, webhook keys |
| `XAIPatterns() []Pattern` | xAI API keys, xAI management API keys |

## Custom patterns

`MustRegexp` builds a pattern from a regular expression, `Regexp` the same for
one that arrives at run time, and `NewPattern` one from a function:

```go
p := mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`)

m := mask.New(mask.WithPatterns(p))

fmt.Println(m.Mask("token: INT-0123456789abcdef0123456789abcdef"))
// token: ************************************
```

Write a counted repetition rather than `+` or `*` for a pattern a stream is to
mask with. The `Pattern` interface can also be implemented directly.

## Streaming

A value written across two writes is in neither of them, so masking each piece
as it arrives redacts nothing. `NewWriter` and `NewReader` hold text back until
the patterns agree nothing more of the stream can change what they found:

```go
w := mask.NewWriter(os.Stderr, m)
defer w.Close()

log.SetOutput(w)
```

Only a tail that could still be the beginning of a value is held, so an ordinary
line goes straight through — and `Close` is what releases the last of it.
`NewReader` masks in the other direction:

```go
body, err := io.ReadAll(mask.NewReader(resp.Body, m))
```

## Redactors

A redactor decides what a located value is redacted to. The default is
`Fill('*')`, which keeps the length of the original; `Fixed` replaces it with a
constant, and `NewRedactor` builds one from a function that can vary by the
pattern that located the value:

```go
m := mask.New(
	mask.WithPatterns(mask.AllBuiltinPatterns()...),
	mask.WithRedactor(mask.Fixed("[REDACTED]")),
)

fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
// GITHUB_TOKEN=[REDACTED]
```

## License

[MIT](./LICENSE)
