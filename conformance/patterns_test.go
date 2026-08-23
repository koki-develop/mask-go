// The pattern sets a corpus case is masked with, named so that a case says
// which one it uses and nothing more.
//
// Beside the built-in sets there are sets built from patterns of this file's
// own. The rules a Masker resolves overlapping values by, and the spans it
// ignores, belong to no built-in pattern and cannot be stated with one: a
// built-in locates what it locates, and no input makes two of them overlap the
// way the rules describe. A pattern that looks for a given substring, or one
// that reports given spans whatever it is handed, states those rules on inputs
// a reader can follow.

package conformance

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/koki-develop/mask-go"
)

// substringPattern returns a Pattern reporting name that locates every
// occurrence of want.
//
// A pattern for the empty string locates nothing rather than everything: the
// scan below would report an empty span at every position and never advance,
// and this helper is wired into a fuzz target, where a hang is thirty seconds
// of nothing rather than a failure to read.
func substringPattern(name, want string) mask.Pattern {
	return mask.NewPattern(name, func(src string) []mask.Span {
		if want == "" {
			return nil
		}
		var spans []mask.Span
		for i := 0; ; {
			j := strings.Index(src[i:], want)
			if j < 0 {
				return spans
			}
			spans = append(spans, mask.Span{Start: i + j, End: i + j + len(want)})
			i += j + len(want)
		}
	})
}

// spansPattern returns a Pattern reporting name that reports spans whatever it
// is handed. A case using one is written against a fixed input, named in the
// case beside it.
func spansPattern(name string, spans ...mask.Span) mask.Pattern {
	return mask.NewPattern(name, func(string) []mask.Span { return spans })
}

// patternSets is what the patterns field of a case names.
//
// A case that names none is masked with what the last patterns directive above
// it named, and with "default" only where no directive stands above it — the
// built-in patterns as AllBuiltinPatterns reports them, which is how the
// library is used. The name is the notation's, for the set a case falls back
// to, and says nothing about which patterns a caller ought to reach for.
var patternSets = map[string][]mask.Pattern{
	// The built-in patterns, together and one at a time. A pattern alone is
	// what says the pattern locates a value on its own; the whole set is what
	// says the sets do not interfere.
	"default":               mask.AllBuiltinPatterns(),
	"anthropic-api-key":     {mask.AnthropicAPIKey()},
	"aws-access-key-id":     {mask.AWSAccessKeyID()},
	"github-token":          {mask.GitHubToken()},
	"gitlab-token":          {mask.GitLabToken()},
	"google-api-key":        {mask.GoogleAPIKey()},
	"hashicorp-vault-token": {mask.HashiCorpVaultToken()},
	"jwt":                   {mask.JWT()},
	"linear-api-key":        {mask.LinearAPIKey()},
	"notion-api-token":      {mask.NotionAPIToken()},
	"npm-token":             {mask.NPMToken()},
	"openai-api-key":        {mask.OpenAIAPIKey()},
	"pypi-api-token":        {mask.PyPIAPIToken()},
	"sendgrid-api-key":      {mask.SendGridAPIKey()},
	"sentry-auth-token":     {mask.SentryAuthToken()},
	"slack-token":           {mask.SlackToken()},
	"stripe-api-key":        {mask.StripeAPIKey()},

	// No pattern at all: a Masker given none redacts nothing.
	"none": {},

	// The patterns a caller builds.
	"regexp":            {mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`)},
	"regexp-mask-group": {mask.MustRegexp("user-id", `user_id=(?P<mask>\d+)`)},
	// A marker written in variants is one alternation with the group named in
	// each branch, which Go admits and MustRegexp reads all of.
	"regexp-mask-group-branches": {mask.MustRegexp("key", `key_(?:live_(?P<mask>[0-9a-f]+)|test_(?P<mask>[0-9a-f]+))`)},
	"func":                       {substringPattern("shared-secret", "s3cr3t-value")},
	"default-and-regexp": append(
		mask.AllBuiltinPatterns(),
		mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`),
	),

	// The rules by which values that overlap are merged, and the one the
	// combined text is attributed to. Each set is written against the input
	// "xxabcdefxx" or a part of it, so that the spans are readable from the
	// case.
	"earlier-and-later":          {substringPattern("early", "abcd"), substringPattern("late", "cdef")},
	"earlier-and-later-reversed": {substringPattern("late", "cdef"), substringPattern("early", "abcd")},
	"same-start":                 {substringPattern("short", "ab"), substringPattern("long", "abcd")},
	"same-start-reversed":        {substringPattern("long", "abcd"), substringPattern("short", "ab")},
	"same-span":                  {substringPattern("first", "abcd"), substringPattern("second", "abcd")},
	"same-span-reversed":         {substringPattern("second", "abcd"), substringPattern("first", "abcd")},
	"containing":                 {substringPattern("outer", "abcdef"), substringPattern("inner", "cd")},
	"containing-reversed":        {substringPattern("inner", "cd"), substringPattern("outer", "abcdef")},
	"chained":                    {substringPattern("first", "abc"), substringPattern("second", "cde"), substringPattern("third", "efg")},
	"adjacent":                   {substringPattern("first", "ab"), substringPattern("second", "cd")},

	// The spans Find is documented to have ignored. Every set here is written
	// against the input "abcdef", six bytes long.
	"span-empty":        {spansPattern("empty", mask.Span{Start: 2, End: 2})},
	"span-reversed":     {spansPattern("reversed", mask.Span{Start: 4, End: 2})},
	"span-negative":     {spansPattern("negative", mask.Span{Start: -1, End: 2})},
	"span-past-the-end": {spansPattern("past-the-end", mask.Span{Start: 4, End: 7})},
	"span-unusable-beside-a-value": {spansPattern("mixed",
		mask.Span{Start: 4, End: 7},
		mask.Span{Start: 3, End: 3},
		mask.Span{Start: 0, End: 2},
	)},
	"span-unordered": {spansPattern("unordered",
		mask.Span{Start: 4, End: 6},
		mask.Span{Start: 0, End: 2},
	)},
	"span-duplicated": {spansPattern("duplicated",
		mask.Span{Start: 0, End: 2},
		mask.Span{Start: 0, End: 2},
	)},
	"span-whole-input": {spansPattern("whole", mask.Span{Start: 0, End: 6})},
}

// reversed returns the patterns of a set in the opposite order. Which values
// are redacted may not depend on the order patterns were given in; only which
// pattern the redaction is attributed to may.
func reversed(patterns []mask.Pattern) []mask.Pattern {
	out := slices.Clone(patterns)
	slices.Reverse(out)
	return out
}

func Test_patternSets_areUsable(t *testing.T) {
	// A set is what every property of a case is driven through, so an empty
	// entry, or one holding a pattern twice, would weaken every case naming it
	// without failing anywhere else.
	for _, name := range slices.Sorted(maps.Keys(patternSets)) {
		t.Run(name, func(t *testing.T) {
			set := patternSets[name]
			if name != "none" && len(set) == 0 {
				t.Fatal("the set holds no pattern")
			}
			seen := make(map[string]bool, len(set))
			for _, p := range set {
				if p == nil {
					t.Fatal("the set holds a nil pattern")
				}
				if p.Name() == "" {
					t.Error("the set holds a pattern with no name")
				}
				if seen[p.Name()] {
					t.Errorf("the set names %q twice, so attribution cannot be read from a case", p.Name())
				}
				seen[p.Name()] = true

				// A name is written into the annotated text ahead of the value
				// it located, so a name carrying what the notation is built
				// from would be read back as something else.
				if strings.ContainsAny(p.Name(), ":"+string(markOpen)+string(markClose)) {
					t.Errorf("the name %q holds a character the notation is built from", p.Name())
				}
			}
		})
	}
}

func Test_patternSets_holdEveryBuiltinAlone(t *testing.T) {
	// Every built-in must have a set holding it and nothing else. It is what a
	// case names to state what that pattern locates on its own, and what the
	// clean cases TestCorpus_coversEveryBuiltinPattern counts are masked with —
	// a pattern with no set of its own cannot be stated apart from the others.
	for _, p := range mask.AllBuiltinPatterns() {
		t.Run(p.Name(), func(t *testing.T) {
			for _, set := range patternSets {
				if len(set) == 1 && set[0] == p {
					return
				}
			}
			t.Errorf("no pattern set holds %s and nothing else", p.Name())
		})
	}
}

func Test_substringPattern_emptyWant(t *testing.T) {
	if spans := substringPattern("empty", "").Find("abcdef"); len(spans) != 0 {
		t.Errorf("Find() = %v, want nothing at all", spans)
	}
}

func Test_patternSets_doNotShareTheirSlice(t *testing.T) {
	// Two sets built from AllBuiltinPatterns must not append into the same array,
	// which is what a set built as append(AllBuiltinPatterns(), ...) would do were
	// AllBuiltinPatterns to hand out the slice it keeps.
	def := patternSets["default"]
	both := patternSets["default-and-regexp"]
	if len(both) != len(def)+1 {
		t.Fatalf("default-and-regexp holds %d pattern(s), default holds %d", len(both), len(def))
	}
	for i, p := range def {
		if both[i] != p {
			t.Errorf("default-and-regexp[%d] is %q, want %q", i, both[i].Name(), p.Name())
		}
	}
}
