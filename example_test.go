package mask_test

import (
	"fmt"
	"io"
	"log"
	"os"
	"slices"
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

	fmt.Println(m.Mask("secret=sk_live_0123456789abcdef01234567 publishable=pk_live_0123456789abcdef01234567 webhook=whsec_0123456789abcdef0123456789abcdef"))
	// Output: secret=******************************** publishable=******************************** webhook=**************************************
}

func ExampleAWSPatterns() {
	// Concatenating two vendors' accessors is how a caller reaches for some of
	// the registry and not all of it, which is what a Masker built from
	// AllBuiltinPatterns cannot do.
	m := mask.New(mask.WithPatterns(slices.Concat(
		mask.AWSPatterns(),
		mask.GitHubPatterns(),
	)...))

	fmt.Println(m.Mask("AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF AWS_SECRET_ACCESS_KEY=0123456789abcdef0123456789abcdef01234567 gh=ghp_0123456789abcdefghijklmnopqrstuvwxyz gl=glpat-0123456789abcdefghij"))
	// Output: AWS_ACCESS_KEY_ID=******************** AWS_SECRET_ACCESS_KEY=**************************************** gh=**************************************** gl=glpat-0123456789abcdefghij
}

func ExampleCloudflarePatterns() {
	m := mask.New(mask.WithPatterns(mask.CloudflarePatterns()...))

	fmt.Println(m.Mask("key=cfk_0123456789abcdef0123456789abcdef0123456789abcdef token=cfut_0123456789abcdef0123456789abcdef0123456789abcdef"))
	// Output: key=**************************************************** token=*****************************************************
}

func ExampleDatabricksPatterns() {
	m := mask.New(mask.WithPatterns(mask.DatabricksPatterns()...))

	fmt.Println(m.Mask("pat=dapi0123456789abcdef0123456789abcdef secret=dose0123456789abcdef0123456789abcdef"))
	// Output: pat=************************************ secret=************************************
}

func ExampleHashiCorpPatterns() {
	m := mask.New(mask.WithPatterns(mask.HashiCorpPatterns()...))

	fmt.Println(m.Mask("vault=hvs.0123456789abcdef01234567 tfc=0123456789abcd.atlasv1.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012"))
	// Output: vault=**************************** tfc=******************************************************************************************
}

func ExampleShopifyPatterns() {
	m := mask.New(mask.WithPatterns(mask.ShopifyPatterns()...))

	fmt.Println(m.Mask("token=shpat_0123456789abcdef0123456789abcdef secret=shpss_0123456789abcdef0123456789abcdef"))
	// Output: token=************************************** secret=**************************************
}

func ExampleSupabasePatterns() {
	m := mask.New(mask.WithPatterns(mask.SupabasePatterns()...))

	fmt.Println(m.Mask("access=sbp_0123456789abcdef0123456789abcdef01234567 publishable=sb_publishable_0123456789abcdef012345_01234567 secret=sb_secret_0123456789abcdef012345_01234567"))
	// Output: access=******************************************** publishable=********************************************** secret=*****************************************
}

func ExampleAWSAccessKeyID() {
	m := mask.New(mask.WithPatterns(mask.AWSAccessKeyID()))

	fmt.Println(m.Mask("AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF"))
	// Output: AWS_ACCESS_KEY_ID=********************
}

func ExampleAWSSecretAccessKey() {
	// The value carries nothing to be recognised by — forty characters of
	// base64 are as much a git object as a key — so this pattern reads the name
	// the value is assigned to, and redacts the value alone. The name is what
	// stays behind to say which credential leaked.
	m := mask.New(mask.WithPatterns(mask.AWSSecretAccessKey()))

	fmt.Println(m.Mask("AWS_SECRET_ACCESS_KEY=0123456789abcdef0123456789abcdef01234567"))
	// Output: AWS_SECRET_ACCESS_KEY=****************************************
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
	// secret and organization keys not, so a pattern of its own reads each side
	// of that column. Reaching for this one alone redacts the keys that matter
	// and leaves the publishable key, which belongs in the page it initializes.
	m := mask.New(mask.WithPatterns(mask.StripeSecretKey()))

	fmt.Println(m.Mask("secret=sk_live_0123456789abcdef01234567 publishable=pk_live_0123456789abcdef01234567"))
	// Output: secret=******************************** publishable=pk_live_0123456789abcdef01234567
}

func ExampleStripeWebhookSigningSecret() {
	// The signing secret is no row of Stripe's table of key types: it is
	// issued per endpoint rather than per account, and what it authenticates
	// is Stripe to the reader's server rather than the other way about.
	// Reaching for it alone redacts what verifies Stripe's own signature and
	// leaves the API keys, which the patterns beside it read.
	m := mask.New(mask.WithPatterns(mask.StripeWebhookSigningSecret()))

	fmt.Println(m.Mask("secret=whsec_0123456789abcdef0123456789abcdef key=sk_live_0123456789abcdef01234567"))
	// Output: secret=************************************** key=sk_live_0123456789abcdef01234567
}

func ExampleSupabaseSecretKey() {
	// Supabase's secret key is what a server authenticates with; its
	// publishable key is meant to ship in a client and is left alone.
	m := mask.New(mask.WithPatterns(mask.SupabaseSecretKey()))

	fmt.Println(m.Mask("secret=sb_secret_0123456789abcdef012345_01234567 publishable=sb_publishable_0123456789abcdef012345_01234567"))
	// Output: secret=***************************************** publishable=sb_publishable_0123456789abcdef012345_01234567
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

func ExampleWithPatterns_selected() {
	// A short, named list rather than the whole registry: each of the two
	// patterns given here reads what it names, and a credential neither of
	// them names — an AWS access key ID, say — is left as written.
	m := mask.New(
		mask.WithPatterns(mask.GitHubToken(), mask.JWT()),
		mask.WithPatterns(mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`)),
	)

	fmt.Println(m.Mask("gh=ghp_0123456789abcdefghijklmnopqrstuvwxyz jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef int=INT-0123456789abcdef0123456789abcdef aws=AKIA0123456789ABCDEF"))
	// Output: gh=**************************************** jwt=************************************************************************ int=************************************ aws=AKIA0123456789ABCDEF
}

func ExampleRegexp() {
	// An expression that arrives at run time — off a flag, or out of a
	// configuration file — is where the error is worth having.
	p, err := mask.Regexp("internal-token", `INT-[0-9a-f]{32}`)
	if err != nil {
		fmt.Println(err)
		return
	}
	m := mask.New(mask.WithPatterns(p))

	fmt.Println(m.Mask("token: INT-0123456789abcdef0123456789abcdef"))
	// Output: token: ************************************
}

func ExampleRegexp_maskGroup() {
	// The literal outside the group survives; only what the group named
	// "mask" matched is redacted.
	p, err := mask.Regexp("bearer-token", `Bearer (?P<mask>[\w.~+/-]+=*)`)
	if err != nil {
		fmt.Println(err)
		return
	}
	m := mask.New(mask.WithPatterns(p))

	fmt.Println(m.Mask("Authorization: Bearer abc123"))
	// Output: Authorization: Bearer ******
}

func ExampleMustRegexp() {
	p := mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`)

	m := mask.New(mask.WithPatterns(p))

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

	p := mask.NewPattern("shared-secret", func(src string) ([]mask.Span, int) {
		var spans []mask.Span
		for i := 0; ; {
			j := strings.Index(src[i:], secret)
			if j < 0 {
				break
			}
			spans = append(spans, mask.Span{Start: i + j, End: i + j + len(secret)})
			// One byte past where this one began, not past where it ended: a
			// value written inside another is a value, and a scan resuming
			// past the match would step over it. LookBehind asks for the same
			// thing from the other side — where a scan resumes must not depend
			// on how much of the text in front of it it was shown.
			i += j + 1
		}
		// The value is one fixed width, so text further than a width from
		// the end of src holds nothing more of it to come.
		return spans, max(0, len(src)-len(secret)+1)
	})

	m := mask.New(mask.WithPatterns(p))

	fmt.Println(m.Mask("password=s3cr3t-value"))
	// Output: password=************
}

// sharedSecret is a Pattern implemented directly on a named type, rather than
// through NewPattern's closure — the other way README.md says the interface
// may be satisfied.
type sharedSecret string

func (s sharedSecret) Name() string { return "shared-secret" }

func (s sharedSecret) Find(src string) ([]mask.Span, int) {
	var spans []mask.Span
	for i := 0; ; {
		j := strings.Index(src[i:], string(s))
		if j < 0 {
			break
		}
		spans = append(spans, mask.Span{Start: i + j, End: i + j + len(s)})
		i += j + 1
	}
	return spans, max(0, len(src)-len(s)+1)
}

func ExamplePattern() {
	m := mask.New(mask.WithPatterns(sharedSecret("s3cr3t-value")))

	fmt.Println(m.Mask("password=s3cr3t-value"))
	// Output: password=************
}

func ExampleWithRedactor() {
	// Without WithRedactor, a Masker redacts with Fill('*'), which keeps the
	// length of what it replaces.
	def := mask.New(mask.WithPatterns(mask.GitHubToken()))
	custom := mask.New(
		mask.WithPatterns(mask.GitHubToken()),
		mask.WithRedactor(mask.Fixed("[REDACTED]")),
	)

	src := "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	fmt.Println(def.Mask(src))
	fmt.Println(custom.Mask(src))
	// Output:
	// GITHUB_TOKEN=****************************************
	// GITHUB_TOKEN=[REDACTED]
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

func ExampleNewRedactor_byName() {
	m := mask.New(
		mask.WithPatterns(mask.AllBuiltinPatterns()...),
		mask.WithRedactor(mask.NewRedactor(func(m mask.Match) string {
			if m.Pattern.Name() == "jwt" {
				return "[JWT]"
			}
			return "[REDACTED]"
		})),
	)

	fmt.Println(m.Mask("jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef gh=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
	// Output: jwt=[JWT] gh=[REDACTED]
}

func ExampleMatch() {
	m := mask.New(
		mask.WithPatterns(mask.GitHubToken()),
		mask.WithRedactor(mask.NewRedactor(func(m mask.Match) string {
			fmt.Printf("%s: %s\n", m.Pattern.Name(), m.Value)
			return "[REDACTED]"
		})),
	)

	fmt.Println(m.Mask("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"))
	// Output:
	// github-token: ghp_0123456789abcdefghijklmnopqrstuvwxyz
	// GITHUB_TOKEN=[REDACTED]
}

func ExampleNewWriter() {
	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))

	w := mask.NewWriter(os.Stdout, m)

	// A value split across two writes is in neither of them, so the first
	// half is held back until the second arrives.
	for _, piece := range []string{"GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstu", "vwxyz\n"} {
		if _, err := io.WriteString(w, piece); err != nil {
			panic(err)
		}
	}

	// Close writes out whatever the Writer is still holding back. A Writer
	// that is never closed leaves it unwritten.
	if err := w.Close(); err != nil {
		panic(err)
	}
	// Output: GITHUB_TOKEN=****************************************
}

func ExampleNewWriter_logger() {
	// A Writer behind a logger holds a line back only until the logger's own
	// newline settles it, so a credential a log line carries is redacted as
	// that call returns rather than one line later.
	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))
	w := mask.NewWriter(os.Stdout, m)

	l := log.New(w, "", 0)
	l.Println("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz")
	l.Println("connection refused")

	if err := w.Close(); err != nil {
		panic(err)
	}
	// Output:
	// GITHUB_TOKEN=****************************************
	// connection refused
}

func ExampleNewReader() {
	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))

	src := strings.NewReader("GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz")
	masked, err := io.ReadAll(mask.NewReader(src, m))
	if err != nil {
		panic(err)
	}

	fmt.Println(string(masked))
	// Output: GITHUB_TOKEN=****************************************
}

func ExampleWithMaxRetained() {
	// A run of the characters a key is written in, arriving without end, is a
	// key without end to the pattern reading it. The limit is where holding
	// stops, and what it stops with is a redaction of everything held.
	m := mask.New(
		mask.WithPatterns(mask.StripeSecretKey()),
		mask.WithRedactor(mask.Fixed("[REDACTED]")),
	)

	w := mask.NewWriter(os.Stdout, m, mask.WithMaxRetained(32))
	if _, err := io.WriteString(w, "sk_live_"+strings.Repeat("0123456789abcdef", 8)); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	// Output: [REDACTED]
}
