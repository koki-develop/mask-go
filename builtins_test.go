package mask

import (
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// builtinPatterns is what every built-in pattern is held to, one entry a
// pattern. A pattern added to builtins in builtins.go is added here as well,
// and the tests below then hold it to the properties every built-in shares, so
// that it arrives with them already in force rather than with each one written
// out by hand.
//
// The samples say only "this is one of these", which is all the properties
// need. What exactly is located, and what is left alone, is written out case by
// case in the builtin_<name>_test.go beside the pattern instead; the tables
// there stay the statement of behaviour and each of their cases still carries
// its own input.
//
// The anchors say the opposite of a sample: what opens a candidate of this kind
// with a body too short to be a value, so that a scan reaches for one and drops
// it. TestMasker_Mask_withoutMatchDoesNotAllocate (mask_test.go) is what reads
// them, and it needs one from every built-in — a scan whose anchor is missing
// there is never reached, and the allocation it might do per candidate goes
// measured by prose that opens no candidate at all. Naming them here is what
// makes that reach the whole registry: written out as one string in that test,
// the anchors of a pattern added later are simply absent, and nothing reports
// the hole.
//
// What is held of an anchor is that it is not a value, which
// Test_builtins_anchorsAreNotValues drives. That it opens a candidate at all is
// not held and cannot be: opening one is a step inside a scan, and a scan
// reports spans rather than the positions it looked at, so an anchor spelled
// wrongly and one that turns a scan away on its first byte report the same
// nothing. It is a choice made where the scan was written, by whoever knew what
// the cheapest rejection there costs, and it is written here rather than in the
// test so that changing the scan and changing the anchor are the same edit.
//
// The benchmarks are named rather than written out for the same reason and one
// more: what is worth timing in a scan is crafted against what that one scan
// remembers, so it belongs beside it, while what times it is BenchmarkBuiltins
// reading this table. That is what holds a pattern to being timed at all — a
// benchmark written as a function a pattern could be left unwritten for a
// pattern and nothing would say so — and it puts every case under
// Test_builtins_benchmarkCasesHoldTheirValues, which holds it to the count it
// states without -bench being run.
var builtinPatterns = []struct {
	name       string                 // what Name() must report
	pattern    func() Pattern         // the exported accessor
	ref        func(string) []Span    // the plain implementation the scan must agree with
	samples    []string               // inputs holding a value of this kind
	anchors    []string               // what opens a candidate, too short to be a value
	benchmarks func() []benchmarkCase // what the scan is timed on
}{
	{
		name:    "anthropic-api-key",
		pattern: AnthropicAPIKey,
		ref:     referenceAnthropicAPIKeyFind,
		samples: []string{
			"ANTHROPIC_API_KEY=sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			"sk-ant-admin01-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			"sk-ant-oat01-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			"sk-ant-api03-0123456789abcdef-123456789abcdef_123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			"sk-ant-a-sk-ant-api03-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
		},
		anchors:    []string{"sk-ant-"},
		benchmarks: anthropicAPIKeyFindBenchmarks,
	},
	{
		name:    "aws-access-key-id",
		pattern: AWSAccessKeyID,
		ref:     referenceAWSAccessKeyIDFind,
		samples: []string{
			"AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF",
			"ASIA0123456789ABCDEF",
			"ASIAKIA0123456789ABCDEF",
			"AKIA0123456789ABCDEFASIA0123456789ABCDEF",
		},
		anchors:    []string{"AKIA0123456789ABCDE", "ASIA0123456789ABCDE"},
		benchmarks: awsAccessKeyIDFindBenchmarks,
	},
	{
		name:    "cloudflare-api-key",
		pattern: CloudflareAPIKey,
		ref:     referenceCloudflareAPIKeyFind,
		samples: []string{
			"CLOUDFLARE_API_KEY=cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			"cfk_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			"cfk_0123456789abcdefghijklmnopqrstuvwxyzABCD0123abcd",
			"cfk_cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
			"cfk_0123456789abcdef0123456789abcdef01234567012345cfk_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		anchors:    []string{"cfk_0123"},
		benchmarks: cloudflareAPIKeyFindBenchmarks,
	},
	{
		name:    "cloudflare-api-token",
		pattern: CloudflareAPIToken,
		ref:     referenceCloudflareAPITokenFind,
		samples: []string{
			"CLOUDFLARE_API_TOKEN=cfut_0123456789abcdef0123456789abcdef0123456789abcdef",
			"cfat_0123456789abcdef0123456789abcdef0123456789abcdef",
			"cfut_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			"cfut_0123456789abcdefghijklmnopqrstuvwxyzABCD0123abcd",
			"cfut_cfut_0123456789abcdef0123456789abcdef0123456789abcdef",
			"cfut_0123456789abcdef0123456789abcdef012345670123abcfut_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		anchors:    []string{"cfut_0123", "cfat_0123"},
		benchmarks: cloudflareAPITokenFindBenchmarks,
	},
	{
		name:    "github-token",
		pattern: GitHubToken,
		ref:     referenceGitHubTokenFind,
		samples: []string{
			"GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			"gho_0123456789abcdefghijklmnopqrstuvwxyz",
			"github_pat_0123456789abcdefABCDEF_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW",
			"ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			"ghu_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			"ghs_0123456789abcdefghijklmnopqrstuvwxyz0123_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
		anchors:    []string{"ghp_0123456789", "github_pat_0"},
		benchmarks: githubTokenFindBenchmarks,
	},
	{
		name:    "gitlab-token",
		pattern: GitLabToken,
		ref:     referenceGitLabTokenFind,
		samples: []string{
			"GITLAB_TOKEN=glpat-0123456789abcdefghij",
			"gldt-0123456789abcdefghij",
			"glimt-0123456789abcdefghijklmno",
			"gloas-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01",
			"glcbt-0f_0123456789abcdefghij",
			"glptt-0123456789abcdefghij",
			"glptt-0123456789abcdefghijklmnopqrst",
			"glpat-0123456789abcdefghijklmnopq.012345678",
			"glpat-0123456789abcdefghijklmnopq.01.012345678",
			"glrt-t1_0123456789abcdefghijklmnopq.012345678",
			"glpat-0123456789abcdefglpat-0123456789abcdefghij",
		},
		anchors:    []string{"glpat-0"},
		benchmarks: gitLabTokenFindBenchmarks,
	},
	{
		name:    "google-api-key",
		pattern: GoogleAPIKey,
		ref:     referenceGoogleAPIKeyFind,
		samples: []string{
			"GOOGLE_API_KEY=AIza0123456789abcdefghijklmnopqrstuvwxy",
			"AIza0123456789abcdef-hijklmnopqrstuvwx_",
			"AIzaAIza0123456789abcdefghijklmnopqrstuvwxy",
			"AIza0123456789abcdefghijklmnopqrstuvwxyAIza0123456789abcdefghijklmnopqrstuvwxy",
		},
		anchors:    []string{"AIza0"},
		benchmarks: googleAPIKeyFindBenchmarks,
	},
	{
		name:    "grafana-service-account-token",
		pattern: GrafanaServiceAccountToken,
		ref:     referenceGrafanaServiceAccountTokenFind,
		samples: []string{
			"GRAFANA_TOKEN=glsa_0123456789abcdef0123456789abcdef_01234567",
			"glsa_0123456789ABCDEF0123456789ABCDEF_0123ABCD",
			"glsa_0123456789abcdef0123456789abcdef_01234567glsa_0123456789abcdef0123456789abcdef_01234567",
			"glsa_0123456789abcdef0123456789abglsa_012345670123456789abcdef01234567_89abcdef",
		},
		anchors:    []string{"glsa_0123"},
		benchmarks: grafanaServiceAccountTokenFindBenchmarks,
	},
	{
		name:    "hashicorp-vault-token",
		pattern: HashiCorpVaultToken,
		ref:     referenceHashiCorpVaultTokenFind,
		samples: []string{
			"VAULT_TOKEN=hvs.0123456789abcdef01234567",
			"hvb.0123456789abcdef0123456789abcdef0123456789abcdef",
			"hvr.0123456789abcdef01234567",
			"hvs.0123456789abcdef-123456789_bcdef0123456789abcdef",
			"hvs.0123456789abcdef01234hvs.0123456789abcdef01234567",
		},
		anchors:    []string{"hvs.0123", "hvb.0123", "hvr.0123"},
		benchmarks: hashiCorpVaultTokenFindBenchmarks,
	},
	{
		name:    "jwt",
		pattern: JWT,
		ref:     referenceJWTFind,
		samples: []string{
			"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.",
			"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.encKEY123.iv12345.ciphertextABC.authTAGxyz",
			"eyIwIjoxLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
		anchors:    []string{"ey.ey.ey"},
		benchmarks: jwtFindBenchmarks,
	},
	{
		name:    "linear-api-key",
		pattern: LinearAPIKey,
		ref:     referenceLinearAPIKeyFind,
		samples: []string{
			"LINEAR_API_KEY=lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123",
			"lin_api_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
			"lin_api_0123456789abcdefghijklmnopqrstuvwxyz01234",
			"lin_api_0123456789abcdefghijklmnopqrstuvwxyz0lin_api_0123456789abcdefghijklmnopqrstuvwxyz0123",
		},
		anchors:    []string{"lin_api_0"},
		benchmarks: linearAPIKeyFindBenchmarks,
	},
	{
		name:    "notion-api-token",
		pattern: NotionAPIToken,
		ref:     referenceNotionAPITokenFind,
		samples: []string{
			"NOTION_TOKEN=ntn_0123456789abcdef0123456789abcdef0123456789abcd",
			"secret_0123456789abcdef0123456789abcdef0123456789a",
			"ntn_0123456789ABCDEF0123456789ABCDEF0123456789ABCD",
			"ntn_0123456789abcdef0123456789abcdef0123456789antn_0123456789abcdef0123456789abcdef0123456789abcd",
			"secret_0123456789abcdef0123456789abcdef01234secret_0123456789abcdef0123456789abcdef0123456789a",
		},
		anchors:    []string{"ntn_0123", "secret_0123"},
		benchmarks: notionAPITokenFindBenchmarks,
	},
	{
		name:    "npm-access-token",
		pattern: NPMAccessToken,
		ref:     referenceNPMAccessTokenFind,
		samples: []string{
			"NPM_TOKEN=npm_0123456789abcdefghijklmnopqrstuvwxyz",
			"npm_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			"npm_0123456789abcdefghijklmnopqrstuvwxyz0",
			"npm_0123456789abcdefghijklmnopqrstuvwnpm_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		anchors:    []string{"npm_0123"},
		benchmarks: npmAccessTokenFindBenchmarks,
	},
	{
		name:    "openai-api-key",
		pattern: OpenAIAPIKey,
		ref:     referenceOpenAIAPIKeyFind,
		samples: []string{
			"OPENAI_API_KEY=sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
			"sk-svcacct-0123456789abcdefT3BlbkFJ0123456789abcdef",
			"sk-admin-0123456789abcdefT3BlbkFJ0123456789abcdef",
			"sk-0123456789abcdefT3BlbkFJ0123456789abcdef",
			"sk-proj-0123456789abcdef-0123456789abcdef_T3BlbkFJ0123456789abcdef",
			"sk-sk-proj-0123456789abcdefT3BlbkFJ0123456789abcdef",
		},
		anchors:    []string{"sk-T3BlbkF"},
		benchmarks: openAIAPIKeyFindBenchmarks,
	},
	{
		name:    "openrouter-api-key",
		pattern: OpenRouterAPIKey,
		ref:     referenceOpenRouterAPIKeyFind,
		samples: []string{
			"OPENROUTER_API_KEY=sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"sk-or-v1-0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			"sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
			"sk-or-v1-sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefsk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		anchors:    []string{"sk-or-v1-0"},
		benchmarks: openRouterAPIKeyFindBenchmarks,
	},
	{
		name:    "private-key",
		pattern: PrivateKey,
		ref:     referencePrivateKeyFind,
		samples: []string{
			"-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----",
			"-----BEGIN OPENSSH PRIVATE KEY-----\n0123456789abcdef\n-----END OPENSSH PRIVATE KEY-----",
			"-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n0123456789abcdef\n=0123\n-----END PGP PRIVATE KEY BLOCK-----",
			`{"private_key":"-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----\n"}`,
			"-----BEGIN PRIVATE KEY-----\r\n0123456789abcdef\r\n-----END PRIVATE KEY-----",
			"-----BEGIN PRIVATE KEY-----\n0123456789abcdef",
		},
		anchors:    []string{"-----BEGIN PRIVATE KEY-----"},
		benchmarks: privateKeyFindBenchmarks,
	},
	{
		name:    "pypi-api-token",
		pattern: PyPIAPIToken,
		ref:     referencePyPIAPITokenFind,
		samples: []string{
			"PYPI_API_TOKEN=pypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
			"pypi-AgENdGVzdC5weXBpLm9yZw0123456789abcdef0123456789abcdef0123456789abcdef",
			"pypi-AgEEeC5pbw0123456789abcdef0123456789abcdef0123456789abcdef",
			"pypi-AgE0123456789abcdef0123456789abcdef0123456789abcde",
			"pypi-AgEpypi-AgEIcHlwaS5vcmc0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		anchors:    []string{"pypi-AgE"},
		benchmarks: pypiAPITokenFindBenchmarks,
	},
	{
		name:    "rubygems-api-key",
		pattern: RubyGemsAPIKey,
		ref:     referenceRubyGemsAPIKeyFind,
		samples: []string{
			"RUBYGEMS_API_KEY=rubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
			"rubygems_abcdef0123456789abcdef0123456789abcdef0123456789",
			"rubygems_rubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
			"rubygems_0123456789abcdef0123456789abcdef0123456789abcdefrubygems_0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		anchors:    []string{"rubygems_0123"},
		benchmarks: rubyGemsAPIKeyFindBenchmarks,
	},
	{
		name:    "sendgrid-api-key",
		pattern: SendGridAPIKey,
		ref:     referenceSendGridAPIKeyFind,
		samples: []string{
			"SENDGRID_API_KEY=SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			"SG.0123456789abcdef-hij_l.0123456789abcdefghijklmnopqrstuvwxy-ABCDE_G",
			"SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDESG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			"SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGSG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
		},
		anchors:    []string{"SG.0.0"},
		benchmarks: sendGridAPIKeyFindBenchmarks,
	},
	{
		name:    "sentry-auth-token",
		pattern: SentryAuthToken,
		ref:     referenceSentryAuthTokenFind,
		samples: []string{
			"SENTRY_AUTH_TOKEN=sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"sntrya_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"sntryi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"sntrys_0123456789abcdefghijklmnopqrstuv_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			"sntrys_0123456789abcdefghijklmnopqrst==_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			"sntrys_0123456789abcdefghijklmnopqrs+/v_0123456789abcdefghijklmnopqrstuvwxyzABCDE+/",
			"sntrys_0123456789abcdef0123456789sntrys_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
			"sntrys_0123456789abcdef0123456789sntryu_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		anchors:    []string{"sntrys_", "sntryu_"},
		benchmarks: sentryAuthTokenFindBenchmarks,
	},
	{
		name:    "slack-token",
		pattern: SlackToken,
		ref:     referenceSlackTokenFind,
		samples: []string{
			"SLACK_BOT_TOKEN=xoxb-0123456789ab-0123456789abc-0123456789abcdefghijklmn",
			"xoxp-0123456789ab-0123456789abc-0123456789abcd-0123456789abcdef0123456789abcdef",
			"xapp-1-A0123456789-0123456789abc-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"xwfp-0123456789ab-0123456789abcdefghijklmn",
			"xoxe-1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"xoxe.xoxb-1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"xoxb-xoxb-xoxb-xoxb-0123456789abcdefghijklmn",
		},
		anchors:    []string{"xoxb-0"},
		benchmarks: slackTokenFindBenchmarks,
	},
	{
		name:    "stripe-publishable-key",
		pattern: StripePublishableKey,
		ref:     referenceStripePublishableKeyFind,
		samples: []string{
			"STRIPE_PUBLISHABLE_KEY=pk_live_0123456789abcdef01234567",
			"pk_test_0123456789abcdef01234567",
			"pk_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
			"sk_live_0123456789abcdef01234567_pk_test_0123456789abcdef01234567",
		},
		anchors:    []string{"pk_live_", "pk_test_"},
		benchmarks: stripePublishableKeyFindBenchmarks,
	},
	{
		name:    "stripe-secret-key",
		pattern: StripeSecretKey,
		ref:     referenceStripeSecretKeyFind,
		samples: []string{
			"STRIPE_SECRET_KEY=sk_live_0123456789abcdef01234567",
			"sk_test_0123456789abcdef01234567",
			"rk_live_0123456789abcdef01234567",
			"rk_test_0123456789abcdef01234567",
			"sk_org_0123456789abcdef01234567",
			"sk_org_live_0123456789abcdef01234567",
			"sk_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
			"sk_live_0123456789abcdef01234567pk_test_0123456789abcdef01234567",
		},
		anchors:    []string{"sk_live_", "sk_test_"},
		benchmarks: stripeSecretKeyFindBenchmarks,
	},
	{
		name:    "stripe-webhook-signing-secret",
		pattern: StripeWebhookSigningSecret,
		ref:     referenceStripeWebhookSigningSecretFind,
		samples: []string{
			"STRIPE_WEBHOOK_SECRET=whsec_0123456789abcdef0123456789abcdef",
			"whsec_0123456789ABCDEF0123456789ABCDEF",
			"whsec_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"whsec_0123456789abcdef0123456789awhsec_0123456789abcdef0123456789abcdef",
			"whsec_0123456789abcdef0123456789abcdefwhsec_0123456789ABCDEF0123456789ABCDEF",
		},
		anchors:    []string{"whsec_0123"},
		benchmarks: stripeWebhookSigningSecretFindBenchmarks,
	},
	{
		name:    "supabase-access-token",
		pattern: SupabaseAccessToken,
		ref:     referenceSupabaseAccessTokenFind,
		samples: []string{
			"SUPABASE_ACCESS_TOKEN=sbp_0123456789abcdef0123456789abcdef01234567",
			"sbp_oauth_0123456789abcdef0123456789abcdef01234567",
			"sbp_0123456789abcdef0123456789abcdef01234567sbp_oauth_0123456789abcdef0123456789abcdef01234567",
			"sbp_sbp_0123456789abcdef0123456789abcdef01234567",
		},
		anchors:    []string{"sbp_0123", "sbp_oauth_0123"},
		benchmarks: supabaseAccessTokenFindBenchmarks,
	},
}

// noValueInputs is text no built-in pattern has anything to find in: ordinary
// prose, and the bytes a scan reading one at a time can trip over.
var noValueInputs = []string{
	"",
	"a",
	"there is no credential in this sentence",
	"time=2026-08-17T00:00:00Z level=info msg=\"calling api\"",
	"\x00\x01\x02",
	"\xff\xfe", // not valid UTF-8
	"日本語",
	".",
	"..",
	"_",
	"-",
	"----------------------------------------",
}

// builtinInputs returns what a built-in is driven with: text holding no value
// at all, the samples the pattern named, and every prefix of each of them.
//
// The prefixes stand for the truncation a log line cut to a column limit
// leaves. A value cut short is where a scan reading past the end of its input,
// or resuming past what it has not consumed, shows itself.
func builtinInputs(samples []string) []string {
	inputs := slices.Clone(noValueInputs)
	for _, src := range samples {
		for i := range len(src) + 1 {
			inputs = append(inputs, src[:i])
		}
	}
	return inputs
}

// isPatternNameByte reports whether c may appear in the name of a pattern.
// Pattern.Name asks for a name that is stable, lowercase and hyphenated.
func isPatternNameByte(c byte) bool {
	return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-'
}

// Test_builtins_entriesAreFilledIn comes first in this file deliberately, so
// that it is the test which runs before the ones that would otherwise report a
// half-filled entry badly or not at all.
func Test_builtins_entriesAreFilledIn(t *testing.T) {
	// Every field of an entry is what one of the properties below is driven
	// from, and leaving a field out does not fail there. Six of the properties
	// read builtinInputs, which falls back to text holding no value where an
	// entry names no samples, and a property with nothing to find holds nothing:
	// a pattern locating only two bytes of a token and wired to the wrong
	// reference passes all six with samples omitted. A missing accessor or
	// reference is worse still, panicking and taking the rest of the package
	// down with it rather than failing one case.
	//
	// So an entry is held to being whole here, where the omission is reported as
	// itself. This is what the claim that a pattern arrives with the properties
	// in force rests on. The benchmarks are held to being named for a reason of
	// their own: BenchmarkBuiltins times what this table names and nothing
	// else, so an entry naming none is a scan nobody times, and go test would
	// not report that by itself — it runs no benchmark at all.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			if b.name == "" {
				t.Error("the entry names no pattern")
			}
			if b.pattern == nil {
				t.Error("the entry carries no accessor")
			}
			if b.ref == nil {
				t.Error("the entry carries no reference")
			}
			if len(b.samples) == 0 {
				t.Error("the entry carries no samples")
			}
			if len(b.anchors) == 0 {
				t.Error("the entry carries no anchors")
			}
			if b.benchmarks == nil {
				t.Error("the entry carries no benchmarks")
			}
		})
	}
}

func Test_builtins_anchorsAreNotValues(t *testing.T) {
	// An anchor stands for a candidate that fails, so nothing may locate a value
	// in one. Against every built-in rather than against its own: the anchors
	// are masked with the whole registry in
	// TestMasker_Mask_withoutMatchDoesNotAllocate, so an anchor that is a value
	// of some other pattern breaks that case exactly as one that is a value of
	// its own does. What breaks there is reported as a redaction — the text it
	// was handed having stopped being text that locates nothing — and it is
	// skipped under the race detector besides, so a run of go test -race alone
	// would report nothing at all. Here the anchor is named.
	patterns := AllBuiltinPatterns()
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			for _, a := range b.anchors {
				for _, p := range patterns {
					if spans, _ := p.Find(a); len(spans) != 0 {
						t.Errorf("%s locates %v in the anchor %q; an anchor stands for a candidate a scan drops", p.Name(), spans, a)
					}
				}
			}
		})
	}
}

func Test_builtins_matchAllBuiltinPatterns(t *testing.T) {
	// The table above and the registry in builtins.go must name the same
	// patterns in the same order. A pattern added to one and forgotten in the
	// other would otherwise either go untested or go unreported by
	// AllBuiltinPatterns, and neither shows anywhere else.
	got := AllBuiltinPatterns()
	if len(got) != len(builtinPatterns) {
		t.Fatalf("AllBuiltinPatterns() reports %d pattern(s), the table holds %d", len(got), len(builtinPatterns))
	}
	for i, b := range builtinPatterns {
		if got[i] != b.pattern() {
			t.Errorf("AllBuiltinPatterns()[%d] is %q, the table holds %q", i, got[i].Name(), b.name)
		}
	}
}

func Test_AllBuiltinPatterns_freshEachCall(t *testing.T) {
	first := AllBuiltinPatterns()
	first[0] = fixed("replaced")
	if second := AllBuiltinPatterns(); second[0] == first[0] {
		t.Error("modifying the returned slice changed what a later call returns")
	}
}

func Test_builtins_name(t *testing.T) {
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			if got := b.pattern().Name(); got != b.name {
				t.Errorf("Name() = %q, want %q", got, b.name)
			}

			// Pattern.Name asks for a name that is stable, lowercase and
			// hyphenated, and a caller keying on one reads it as such, so the
			// convention is held to here rather than left to whoever writes
			// the next name.
			if b.name == "" {
				t.Fatal("the name is empty")
			}
			for _, c := range []byte(b.name) {
				if !isPatternNameByte(c) {
					t.Errorf("name %q holds %q, want lowercase letters, digits and hyphens", b.name, c)
				}
			}
			if strings.HasPrefix(b.name, "-") || strings.HasSuffix(b.name, "-") {
				t.Errorf("name %q opens or closes with a hyphen", b.name)
			}
		})
	}
}

func Test_builtins_sameValueEachCall(t *testing.T) {
	// Match carries the Pattern itself, so a caller comparing one against a
	// built-in must get the same value every call. An accessor returning a
	// pattern built on the spot would compare equal to nothing.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			if first, second := b.pattern(), b.pattern(); first != second {
				t.Error("the accessor returned a different value on a second call")
			}
		})
	}
}

func Test_builtins_locateTheirSamples(t *testing.T) {
	// The properties below say what must hold of a located value, which says
	// nothing at all where a sample holds none. Every sample is held to being
	// what it claims first, so that the rest cannot pass vacuously.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			if len(b.samples) == 0 {
				t.Fatal("the entry carries no samples, so nothing below holds anything")
			}
			for _, src := range b.samples {
				if got, _ := b.pattern().Find(src); len(got) == 0 {
					t.Errorf("Find(%q) located nothing, want a value", src)
				}
			}
		})
	}
}

func Test_builtins_findNothingWithoutAValue(t *testing.T) {
	// The other side of the same coin: a pattern eager enough to fire on prose
	// or on a run of punctuation redacts what a caller wanted to keep, and the
	// per-pattern tables only rule out the false positives their author thought
	// of.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			for _, src := range noValueInputs {
				if got, _ := b.pattern().Find(src); len(got) != 0 {
					t.Errorf("Find(%q) = %v, want no span", src, got)
				}
			}
		})
	}
}

func Test_builtins_reportUsableSpans(t *testing.T) {
	// Find is documented to have spans reaching outside src, and spans whose
	// Start is not less than their End, ignored rather than trusted, and
	// Masker.locate duly drops them. A built-in reporting one would therefore
	// go unnoticed there, so the built-ins are held to reporting none.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			p := b.pattern()
			for _, src := range builtinInputs(b.samples) {
				spans, _ := p.Find(src)
				for _, s := range spans {
					if s.Start < 0 || s.End > len(src) || s.Start >= s.End {
						t.Errorf("Find(%q) reported %v, unusable in %d bytes", src, s, len(src))
					}
				}
			}
		})
	}
}

func Test_builtins_matchTheirReference(t *testing.T) {
	// The fuzz target each pattern keeps holds its scan to its reference on
	// generated input, which only a run with -fuzz reaches beyond the corpus.
	// The same holds on the samples and their prefixes under a plain go test,
	// so that a reference wired up to the wrong pattern, or one left behind by
	// a change to the scan, is caught without fuzzing being run at all.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			if b.ref == nil {
				// Calling through a nil reference panics, which takes the rest
				// of the package down instead of failing this one entry.
				t.Fatalf("the entry for %q carries no reference", b.name)
			}
			p := b.pattern()
			for _, src := range builtinInputs(b.samples) {
				got, _ := p.Find(src)
				want := b.ref(src)
				if !slices.Equal(got, want) {
					t.Errorf("Find(%q) = %v, reference gives %v", src, got, want)
				}
			}
		})
	}
}

func Test_builtins_maskLeavesNothingToFind(t *testing.T) {
	// What Mask returns must hold no value the same patterns can still find out
	// of reach of what it redacted: a built-in that passed a value over
	// entirely leaves it to be found again. A value standing against a
	// redaction is another matter, and so is the rest of one whose front was
	// located; checkSecondPass sets out both and says what holds the second.
	// Each pattern is driven alone and beside the others, because a value one
	// pattern locates whole can be one another locates in part, which is how a
	// stateless installation token holds a JWT.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			maskers := map[string]*Masker{
				"alone":           New(WithPatterns(b.pattern())),
				"with the others": New(WithPatterns(AllBuiltinPatterns()...)),
			}
			for name, m := range maskers {
				t.Run(name, func(t *testing.T) {
					for _, src := range builtinInputs(b.samples) {
						checkSecondPass(t, m, src)
					}
				})
			}
		})
	}
}

func Test_builtins_concurrentUse(t *testing.T) {
	// Pattern is documented safe for concurrent use, and several of the
	// built-in scans carry a cursor as they go, the JWT one a decoder as
	// well. Driving a pattern from many goroutines at once puts what it
	// carries under the race detector, and holds its answer to the one a
	// single goroutine gets.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			p := b.pattern()
			inputs := builtinInputs(b.samples)
			want := make([][]Span, len(inputs))
			for i, src := range inputs {
				want[i], _ = p.Find(src)
			}

			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					for range 4 {
						for i, src := range inputs {
							if got, _ := p.Find(src); !slices.Equal(got, want[i]) {
								t.Errorf("Find(%q) = %v, want %v", src, got, want[i])
								return
							}
						}
					}
				})
			}
			wg.Wait()
		})
	}
}

func Test_builtins_benchmarkCasesHoldTheirValues(t *testing.T) {
	// A benchmark case states how many values its text holds, and a case whose
	// text stopped holding them — a count the vendor changed, a character class
	// narrowed — would time the scan finding nothing and report that as a
	// speedup, which is the one failure a benchmark cannot report by itself.
	//
	// benchmarkFind checks the same thing before it starts timing, and this is
	// what does not wait for someone to reach for -bench: go test runs no
	// benchmark, so without this a case could be wrong for as long as nobody
	// measured anything.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			if b.benchmarks == nil {
				// Calling through a nil function panics, which takes the rest
				// of the package down instead of failing this one entry.
				t.Fatalf("the entry for %q names no benchmarks", b.name)
			}
			cases := b.benchmarks()
			if len(cases) == 0 {
				t.Fatal("the entry names a benchmark holding no case")
			}
			p := b.pattern()
			for _, c := range cases {
				spans, _ := p.Find(c.src)
				if got := len(spans); got != c.spans {
					t.Errorf("%s: Find located %d value(s) in %d bytes, the case says %d", c.name, got, len(c.src), c.spans)
				}
			}
		})
	}
}

func Test_builtins_scanIsLinear(t *testing.T) {
	// A scan working out again at every candidate what belongs to the run it
	// sits in costs time quadratic in the length of the input, which is the
	// easiest mistake to make in one. Every sample is repeated to a length at
	// which a quadratic scan cannot finish and a linear one is not noticed, so
	// a new pattern is guarded without anyone writing the guard.
	//
	// The inputs crafted against what a particular scan remembers stay with
	// that scan, in Test_JWT_scanIsLinear: nothing generic reaches a header
	// that reads as JSON to its very end.
	// Two mebibytes is what separates the two costs here rather than merely
	// suggesting a difference. Defeating the run cursor the GitHub scan keeps
	// takes a sample repeated to this length from twelve milliseconds to
	// twenty-one seconds, where at a quarter of a mebibyte it takes it only to
	// a third of a second and passes a bound of any use. The limit is a
	// hundredfold above a linear scan and a tenth of a quadratic one.
	const (
		size  = 2 << 20
		limit = 2 * time.Second
	)

	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			m := New(WithPatterns(b.pattern()))
			for _, sample := range b.samples {
				// Beside the sample repeated whole, a sample cut in half is
				// repeated too. A value that never completes is what leaves a
				// scan resuming one byte along, candidate after candidate,
				// which is where the quadratic cost lives.
				for _, unit := range []string{sample, sample[:len(sample)/2]} {
					if unit == "" {
						continue
					}
					src := strings.Repeat(unit, size/len(unit)+1)
					start := time.Now()
					_ = m.Mask(src)
					if d := time.Since(start); d > limit {
						t.Errorf("Mask() of %d bytes of %q took %v", len(src), unit, d)
					}
				}
			}
		})
	}
}

func Test_builtins_retainSettles(t *testing.T) {
	// What every built-in owes Pattern.Find about the offset it reports: the
	// values in front of it are the values the whole text holds there. A scan
	// settling too much is a value released before it was found, which is the
	// failure this is here for; a scan settling too little costs a stream
	// nothing but the text it holds on to.
	//
	// Every sample is cut at every offset, which is where a scan that forgot
	// the candidate it left open at the end of its input shows itself: the
	// prefix it was handed reaches into a value, and the whole sample is what
	// says where that value really was.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			p := b.pattern()
			for _, src := range builtinInputs(b.samples) {
				for cut := range len(src) + 1 {
					checkRetain(t, p, src, cut)
				}
			}
		})
	}
}

func Test_builtins_retainIsNotBeyondTheInput(t *testing.T) {
	// checkRetain reports this too, but only for a pattern whose samples reach
	// the offset it got wrong. Every input the registry knows about is driven
	// here instead, so that a scan answering past the end of what it was handed
	// is caught by the entry rather than by the sample.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			p := b.pattern()
			for _, src := range append(builtinInputs(b.samples), b.anchors...) {
				if _, retain := p.Find(src); retain < 0 || retain > len(src) {
					t.Errorf("Find(%q) settled %d, outside the %d bytes it was given", src, retain, len(src))
				}
			}
		})
	}
}

func Test_builtins_settleWhatIsNoValue(t *testing.T) {
	// The other direction from Test_builtins_retainSettles, and the one that
	// test cannot report: a scan settling too much releases a value, and a
	// scan settling too little holds a stream open. Held text is not merely
	// late — once a stream is holding more than a caller allows, what it holds
	// goes out redacted — so a scan pinned by text that will never become a
	// value turns a log into asterisks.
	//
	// Every prefix of every sample is followed here by ordinary lines. Whatever
	// a scan made of the prefix, a line break closes every run and a line of
	// prose is no line of any value, so nothing in the prefix reaches through
	// them and the whole of the input is settled.
	tail := "\n" + strings.Repeat("a line of prose, and nothing else at all\n", 40)
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			p := b.pattern()
			for _, sample := range b.samples {
				for i := range len(sample) + 1 {
					src := sample[:i] + tail
					if _, retain := p.Find(src); retain != len(src) {
						t.Errorf("Find(%q + %d lines of prose) settled %d of %d",
							sample[:i], 40, retain, len(src))
					}
				}
			}
		})
	}
}

func Test_builtins_holdNoFurtherBackThanTheCutCandidate(t *testing.T) {
	// The direction Test_builtins_settleWhatIsNoValue cannot reach. That test
	// follows every prefix with lines of prose, so its inputs never end inside
	// a candidate and the branch a scan takes when they do — builtin_scan.go
	// argues there that a scan gives up on such a candidate rather than reading
	// what is written of it — runs in none of its cases. Here the prefix is the
	// end of the input, which is what puts that branch under a test at all.
	//
	// What a scan may give up on there is the candidate the end cut short. The
	// text in front of it was settled before that candidate opened, and no
	// continuation reaches back over a line break to change it, so a scan
	// pinned in front of that candidate gave up on more than the end took from
	// it — and a stream would hold, and at its limit redact, text that was
	// never part of any candidate.
	//
	// Where the candidate opens is what the bound has to be, and an anchor is
	// what says so: it is what opens a candidate of this kind with nothing
	// written in front of it, so behind the prose it opens one exactly where
	// the prose ends. A sample cannot say that. Most carry a lead-in — an
	// environment variable name, a word the value is written against — and a
	// candidate opening inside one and failing is a candidate the scan may
	// give up on as well, so the two are driven here under bounds of different
	// strength rather than under one that is wrong for the samples or toothless
	// for the anchors.
	prose := "a line of prose, and nothing else at all\n"
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			p := b.pattern()

			// The candidate opens where the prose ends, so this is the whole of
			// the rule: the candidate and no more.
			for _, anchor := range b.anchors {
				for i := range len(anchor) + 1 {
					src := prose + anchor[:i]
					if _, retain := p.Find(src); retain < len(prose) {
						t.Errorf("Find(prose + %q) settled %d, in front of the candidate opening at %d",
							anchor[:i], retain, len(prose))
					}
				}
			}

			// And the half of it a sample can be held to, over the bodies an
			// anchor is too short to reach: whatever the scan gave up on, it
			// was not text a line break had closed.
			for _, sample := range b.samples {
				for i := range len(sample) + 1 {
					src := prose + sample[:i]
					if _, retain := p.Find(src); retain < len(prose) {
						t.Errorf("Find(prose + %q) settled %d, in front of the %d bytes of prose handed to it first",
							sample[:i], retain, len(prose))
					}
				}
			}
		})
	}
}
