# mask-go

A Go library for redacting API keys, access tokens and other credentials from text.

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
returns every built-in pattern, and grows as patterns are added:

```go
m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))
```

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
| `AnthropicPatterns()` | Anthropic API keys — the keys the Claude Console issues and the Admin API keys — and the OAuth tokens and session keys Anthropic writes the same way |
| `AWSPatterns()` | AWS access key IDs: the long-term key of an IAM user or of the account root user, and the temporary credentials AWS STS issues |
| `CloudflarePatterns()` | Cloudflare API tokens, the ones a user owns and the ones an account owns, and the Cloudflare API key a user account holds, which carries everything that user can do — in the prefixed format Cloudflare issues today |
| `GitHubPatterns()` | GitHub personal access tokens, classic and fine-grained; OAuth app access tokens; GitHub App user access tokens; GitHub App installation access tokens; and GitHub App refresh tokens |
| `GitLabPatterns()` | GitLab personal, project, group and impersonation access tokens; OAuth application secrets; deploy tokens; runner authentication tokens; CI/CD job tokens; pipeline trigger tokens; feed tokens; incoming mail tokens; GitLab agent for Kubernetes tokens; SCIM OAuth tokens; and feature flags client tokens — in the classic form and the routable one |
| `GooglePatterns()` | Google API keys, the one string every Google API that takes a key rather than a credentialled principal accepts — Maps, YouTube Data, Firebase, the Gemini API and the Cloud APIs reaching no private user data among them |
| `GrafanaPatterns()` | Grafana service account tokens |
| `HashiCorpPatterns()` | HashiCorp Vault service tokens, batch tokens and recovery tokens |
| `JWT()` | JSON Web Tokens in the compact serialization, signed and encrypted alike |
| `LinearPatterns()` | Linear personal API keys |
| `NotionPatterns()` | Notion API tokens: the static token of an internal connection, the OAuth access token of a public one, and a personal access token alike, under both prefixes Notion has issued |
| `NPMPatterns()` | npm access tokens: the granular access tokens npmjs.com issues today, and the classic read-only, automation and publish tokens issued until npm disabled them |
| `OpenAIPatterns()` | OpenAI API keys: project keys, service account keys, Admin API keys, and the user keys issued before projects existed |
| `OpenRouterPatterns()` | OpenRouter API keys |
| `PyPIPatterns()` | PyPI API tokens: the upload tokens pypi.org issues, the ones test.pypi.org issues beside them, and the short-lived ones minted for a Trusted Publisher |
| `RubyGemsPatterns()` | RubyGems.org API keys |
| `SendGridPatterns()` | Twilio SendGrid API keys, whatever access level they carry — full access, custom access and billing access alike |
| `SentryPatterns()` | Sentry user auth tokens, organization auth tokens, user application tokens and internal integration tokens |
| `SlackPatterns()` | Slack bot tokens, user tokens, app-level tokens and workflow tokens, and the pair token rotation issues: refresh tokens and the rotatable bot and user access tokens written behind them |
| `StripePatterns()` | Stripe publishable API keys, restricted API keys, secret API keys and organization API keys |
| `SupabasePatterns()` | Supabase Management API access tokens: the personal access token a user creates for themselves, and the token an OAuth application is issued in that user's name |

`MustRegexp` builds a pattern from a regular expression:

```go
m := mask.New(mask.WithPatterns(
	mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`),
))

fmt.Println(m.Mask("token: INT-0123456789abcdef0123456789abcdef"))
// token: ************************************
```

`NewPattern` builds one from a function. Here, a value known only at run time:

```go
secret := "s3cr3t-value"

p := mask.NewPattern("shared-secret", func(src string) []mask.Span {
	if i := strings.Index(src, secret); i >= 0 {
		return []mask.Span{{Start: i, End: i + len(secret)}}
	}
	return nil
})

m := mask.New(mask.WithPatterns(p))

fmt.Println(m.Mask("password=s3cr3t-value"))
// password=************
```

The `Pattern` interface can also be implemented directly.

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
