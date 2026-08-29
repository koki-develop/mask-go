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

## Patterns

A `Masker` scans only with the patterns it is given. `AllBuiltinPatterns()`
returns every built-in pattern, and grows as patterns are added.

Each vendor also has an accessor of its own, for a caller who wants some of them
and not all:

```go
m := mask.New(mask.WithPatterns(slices.Concat(
	mask.AWSPatterns(),
	mask.GitHubPatterns(),
)...))
```

| Accessor | Locates |
| --- | --- |
| `AgePatterns() []Pattern` | age secret keys (X25519 and MLKEM768-X25519 hybrid identities) |
| `AirtablePatterns() []Pattern` | Airtable personal access tokens |
| `AnthropicPatterns() []Pattern` | Anthropic API keys, Anthropic Admin API keys, Anthropic OAuth tokens, Anthropic session keys |
| `AWSPatterns() []Pattern` | AWS access key IDs, AWS secret access keys |
| `CircleCIPatterns() []Pattern` | CircleCI personal API tokens, project API tokens |
| `CloudflarePatterns() []Pattern` | Cloudflare API tokens, Cloudflare API keys |
| `CratesIOPatterns() []Pattern` | crates.io API tokens, Trusted Publishing access tokens |
| `DatabricksPatterns() []Pattern` | Databricks personal access tokens, Databricks OAuth client secrets |
| `DigitalOceanPatterns() []Pattern` | DigitalOcean personal access tokens, OAuth access tokens, OAuth refresh tokens |
| `DopplerPatterns() []Pattern` | Doppler CLI tokens, personal tokens, service tokens, service account tokens, service account identity tokens, SCIM tokens, audit tokens |
| `GitHubPatterns() []Pattern` | GitHub personal access tokens (classic and fine-grained), GitHub OAuth app access tokens, GitHub App user access tokens, GitHub App installation access tokens, GitHub App refresh tokens |
| `GitLabPatterns() []Pattern` | GitLab personal access tokens, project access tokens, group access tokens, impersonation tokens, OAuth application secrets, deploy tokens, runner authentication tokens, CI/CD job tokens, pipeline trigger tokens, feed tokens, incoming mail tokens, GitLab agent for Kubernetes tokens, SCIM OAuth tokens, feature flags client tokens |
| `GooglePatterns() []Pattern` | Google API keys |
| `GrafanaPatterns() []Pattern` | Grafana service account tokens |
| `HashiCorpPatterns() []Pattern` | HashiCorp Vault service tokens, batch tokens, recovery tokens |
| `HerokuPatterns() []Pattern` | Heroku API tokens |
| `HuggingFacePatterns() []Pattern` | Hugging Face user access tokens |
| `JWT() Pattern` | JSON Web Tokens, signed and encrypted |
| `LinearPatterns() []Pattern` | Linear personal API keys |
| `NotionPatterns() []Pattern` | Notion internal integration tokens, Notion OAuth access tokens, Notion personal access tokens |
| `NPMPatterns() []Pattern` | npm granular access tokens, npm classic tokens (read-only, automation, publish) |
| `OnePasswordPatterns() []Pattern` | 1Password service account tokens |
| `OpenAIPatterns() []Pattern` | OpenAI project API keys, service account keys, Admin API keys, user API keys |
| `OpenRouterPatterns() []Pattern` | OpenRouter API keys |
| `PlanetScalePatterns() []Pattern` | PlanetScale service tokens, OAuth access tokens, OAuth refresh tokens |
| `PostmanPatterns() []Pattern` | Postman API keys |
| `PrivateKey() Pattern` | PKCS#8 private keys, encrypted PKCS#8 private keys, PKCS#1 RSA private keys, EC private keys, DSA private keys, OpenSSH private keys, PGP private key blocks |
| `PulumiPatterns() []Pattern` | Pulumi personal access tokens, organization access tokens, team access tokens |
| `PyPIPatterns() []Pattern` | PyPI API tokens, TestPyPI API tokens, Trusted Publisher tokens |
| `RubyGemsPatterns() []Pattern` | RubyGems.org API keys |
| `SendGridPatterns() []Pattern` | Twilio SendGrid API keys |
| `SentryPatterns() []Pattern` | Sentry user auth tokens, organization auth tokens, user application tokens, internal integration tokens |
| `ShopifyPatterns() []Pattern` | Shopify access tokens (public app, custom app, private app and delegate), Shopify app secret keys |
| `SlackPatterns() []Pattern` | Slack bot tokens, user tokens, app-level tokens, workflow tokens, refresh tokens, rotatable bot and user access tokens |
| `SourcegraphPatterns() []Pattern` | Sourcegraph access tokens |
| `StripePatterns() []Pattern` | Stripe publishable API keys, restricted API keys, secret API keys, organization API keys, webhook signing secrets |
| `SupabasePatterns() []Pattern` | Supabase personal access tokens, Supabase OAuth access tokens, Supabase publishable API keys, Supabase secret API keys |

`MustRegexp` builds a pattern from a regular expression:

```go
m := mask.New(mask.WithPatterns(
	mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`),
))

fmt.Println(m.Mask("token: INT-0123456789abcdef0123456789abcdef"))
// token: ************************************
```

Every match is located, including one that begins inside another: forty
characters of hexadecimal written against forty more are redacted whole.

`NewPattern` builds one from a function. Here, a value known only at run time:

```go
secret := "s3cr3t-value"

p := mask.NewPattern("shared-secret", func(src string) ([]mask.Span, int) {
	var spans []mask.Span
	for i := 0; ; {
		j := strings.Index(src[i:], secret)
		if j < 0 {
			break
		}
		spans = append(spans, mask.Span{Start: i + j, End: i + j + len(secret)})
		i += j + 1
	}
	return spans, max(0, len(src)-len(secret)+1)
})

m := mask.New(mask.WithPatterns(p))

fmt.Println(m.Mask("password=s3cr3t-value"))
// password=************
```

The second result says how far along `src` the answer can no longer change if
more text follows. `Mask` ignores it and [Streaming](#streaming) is what it is
for; returning `0` is always correct.

The `Pattern` interface can also be implemented directly.

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
line goes straight through. `Close` releases whatever is left.

`NewReader` masks in the other direction:

```go
body, err := io.ReadAll(mask.NewReader(resp.Body, m))
```

## Redactors

A redactor decides what a located value is redacted to. `Fill` repeats one rune
for every rune of the original, and is the default as `Fill('*')`:

```go
m := mask.New(
	mask.WithPatterns(mask.AllBuiltinPatterns()...),
	mask.WithRedactor(mask.Fill('#')),
)

fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
// GITHUB_TOKEN=########################################
```

`Fixed` replaces the value with a constant, so its length does not survive:

```go
m := mask.New(
	mask.WithPatterns(mask.AllBuiltinPatterns()...),
	mask.WithRedactor(mask.Fixed("[REDACTED]")),
)

fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
// GITHUB_TOKEN=[REDACTED]
```

`NewRedactor` builds one from a function, which can vary by the pattern that
located the value:

```go
m := mask.New(
	mask.WithPatterns(mask.AllBuiltinPatterns()...),
	mask.WithRedactor(mask.NewRedactor(func(m mask.Match) string {
		return "[" + strings.ToUpper(m.Pattern.Name()) + "]"
	})),
)

fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
// GITHUB_TOKEN=[GITHUB-TOKEN]
```

## License

[MIT](./LICENSE)
