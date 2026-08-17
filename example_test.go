package mask_test

import (
	"fmt"
	"strings"

	"github.com/koki-develop/mask-go"
)

func Example() {
	m := mask.New(mask.WithPatterns(mask.DefaultPatterns()...))

	fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
	// Output: GITHUB_TOKEN=****************************************
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
		mask.WithPatterns(mask.DefaultPatterns()...),
		mask.WithRedactor(mask.Fill('#')),
	)

	fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
	// Output: GITHUB_TOKEN=########################################
}

func ExampleFixed() {
	m := mask.New(
		mask.WithPatterns(mask.DefaultPatterns()...),
		mask.WithRedactor(mask.Fixed("[REDACTED]")),
	)

	fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
	// Output: GITHUB_TOKEN=[REDACTED]
}

func ExampleNewRedactor() {
	m := mask.New(
		mask.WithPatterns(mask.DefaultPatterns()...),
		mask.WithRedactor(mask.NewRedactor(func(m mask.Match) string {
			return "[" + strings.ToUpper(m.Pattern.Name()) + "]"
		})),
	)

	fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
	// Output: GITHUB_TOKEN=[GITHUB-TOKEN]
}
