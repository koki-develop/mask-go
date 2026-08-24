package mask_test

import (
	"fmt"
	"strings"

	"github.com/koki-develop/mask-go"
)

func Example() {
	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))

	fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
	// Output: GITHUB_TOKEN=****************************************
}

func ExampleAllBuiltinPatterns() {
	// The built-in patterns are given to a Masker together, and each of them
	// scans for what it knows.
	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))

	fmt.Println(m.Mask("token=ghp_0123456789abcdefghijklmnopqrstuvwxyz jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef"))
	// Output: token=**************************************** jwt=************************************************************************
}

func ExampleStripePatterns() {
	// Every vendor has an accessor of its own, returning the built-in patterns
	// that read what that vendor issues. A vendor with more than one is given
	// whole by it.
	m := mask.New(mask.WithPatterns(mask.StripePatterns()...))

	fmt.Println(m.Mask("secret=sk_live_0123456789abcdef01234567 publishable=pk_live_0123456789abcdef01234567"))
	// Output: secret=******************************** publishable=********************************
}

func ExampleAWSAccessKeyID() {
	m := mask.New(mask.WithPatterns(mask.AWSAccessKeyID()))

	fmt.Println(m.Mask("AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF"))
	// Output: AWS_ACCESS_KEY_ID=********************
}

func ExampleGitHubToken() {
	m := mask.New(mask.WithPatterns(mask.GitHubToken()))

	fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
	// Output: GITHUB_TOKEN=****************************************
}

func ExampleGitLabToken() {
	m := mask.New(mask.WithPatterns(mask.GitLabToken()))

	fmt.Println(m.Mask("GITLAB_TOKEN=glpat-0123456789abcdefghij"))
	// Output: GITLAB_TOKEN=**************************
}

func ExampleGoogleAPIKey() {
	m := mask.New(mask.WithPatterns(mask.GoogleAPIKey()))

	fmt.Println(m.Mask("GOOGLE_API_KEY=AIza0123456789abcdefghijklmnopqrstuvwxy"))
	// Output: GOOGLE_API_KEY=***************************************
}

func ExampleJWT() {
	m := mask.New(mask.WithPatterns(mask.JWT()))

	fmt.Println(m.Mask("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef"))
	// Output: Authorization: Bearer ************************************************************************
}

func ExampleSlackToken() {
	m := mask.New(mask.WithPatterns(mask.SlackToken()))

	fmt.Println(m.Mask("SLACK_BOT_TOKEN=xoxb-0123456789ab-0123456789abc-0123456789abcdefghijklmn"))
	// Output: SLACK_BOT_TOKEN=********************************************************
}

func ExampleStripeSecretKey() {
	// Stripe marks the publishable key safe to expose and the restricted,
	// secret and organization keys not, so the two are patterns of their own.
	// Reaching for this one alone redacts the keys that matter and leaves the
	// publishable key, which belongs in the page it initializes.
	m := mask.New(mask.WithPatterns(mask.StripeSecretKey()))

	fmt.Println(m.Mask("secret=sk_live_0123456789abcdef01234567 publishable=pk_live_0123456789abcdef01234567"))
	// Output: secret=******************************** publishable=pk_live_0123456789abcdef01234567
}

func ExampleWithPatterns() {
	// Repeated options accumulate, so the built-in patterns and one of your
	// own can be given separately.
	m := mask.New(
		mask.WithPatterns(mask.AllBuiltinPatterns()...),
		mask.WithPatterns(mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`)),
	)

	fmt.Println(m.Mask("github=ghp_0123456789abcdefghijklmnopqrstuvwxyz internal=INT-0123456789abcdef0123456789abcdef"))
	// Output: github=**************************************** internal=************************************
}

func ExampleMustRegexp() {
	m := mask.New(mask.WithPatterns(
		mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`),
	))

	fmt.Println(m.Mask("token: INT-0123456789abcdef0123456789abcdef"))
	// Output: token: ************************************
}

func ExampleMustRegexp_maskGroup() {
	m := mask.New(mask.WithPatterns(
		mask.MustRegexp("user-id", `user_id=(?P<mask>\d+)`),
	))

	fmt.Println(m.Mask("user_id=12345 name=alice"))
	// Output: user_id=***** name=alice
}

func ExampleNewPattern() {
	secret := "s3cr3t-value"

	p := mask.NewPattern("shared-secret", func(src string) []mask.Span {
		if i := strings.Index(src, secret); i >= 0 {
			return []mask.Span{{Start: i, End: i + len(secret)}}
		}
		return nil
	})

	m := mask.New(mask.WithPatterns(p))

	fmt.Println(m.Mask("password=s3cr3t-value"))
	// Output: password=************
}

func ExampleFill() {
	m := mask.New(
		mask.WithPatterns(mask.AllBuiltinPatterns()...),
		mask.WithRedactor(mask.Fill('#')),
	)

	fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
	// Output: GITHUB_TOKEN=########################################
}

func ExampleFixed() {
	m := mask.New(
		mask.WithPatterns(mask.AllBuiltinPatterns()...),
		mask.WithRedactor(mask.Fixed("[REDACTED]")),
	)

	fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
	// Output: GITHUB_TOKEN=[REDACTED]
}

func ExampleNewRedactor() {
	m := mask.New(
		mask.WithPatterns(mask.AllBuiltinPatterns()...),
		mask.WithRedactor(mask.NewRedactor(func(m mask.Match) string {
			return "[" + strings.ToUpper(m.Pattern.Name()) + "]"
		})),
	)

	fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
	// Output: GITHUB_TOKEN=[GITHUB-TOKEN]
}
