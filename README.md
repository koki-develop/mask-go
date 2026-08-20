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
returns every pattern in the table below, and grows as patterns are added:

| Pattern | Locates |
| --- | --- |
| `GitHubToken()` | `ghp_…`, `gho_…`, `ghu_…`, `ghs_…`, `ghr_…`, `github_pat_…` |
| `JWT()` | JSON Web Tokens |

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
