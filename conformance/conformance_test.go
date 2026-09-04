// What every corpus case is held to.
//
// A case states one thing — the text it masks to, with every redaction marked
// and named — and everything below is derived from that one statement. Nothing
// here is written per case, so a case cannot arrive with some of the properties
// and not others, and adding a case is adding a line rather than a test.

package conformance

import (
	"cmp"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/koki-develop/mask-go"
)

func TestConformance(t *testing.T) {
	files := loadCorpus(t)
	if *update {
		regenerate(t, files)
		files = loadCorpus(t) // hold what was written, not what was in hand
	}

	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			for _, c := range f.cases {
				t.Run(c.name, func(t *testing.T) { checkCase(t, c) })
			}
		})
	}
}

// regenerate writes the out field of every case from what the library does now.
// It is what -update runs, and it runs before the checks rather than instead of
// them: a regenerated corpus is held to everything below in the same command
// that wrote it.
func regenerate(t *testing.T, files []*corpusFile) {
	t.Helper()

	for _, f := range files {
		for _, c := range f.cases {
			out, _ := maskMarked(c.patterns(), c.in)
			c.out, c.hasOut = out, true
		}
		data := f.render()
		old, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatalf("reading %s: %v", f.path, err)
		}
		if string(old) == string(data) {
			continue
		}
		if err := os.WriteFile(f.path, data, 0o644); err != nil {
			t.Fatalf("writing %s: %v", f.path, err)
		}
		t.Logf("%s rewritten", f.path)
	}
}

// checkCase holds one case to everything masking must be.
func checkCase(t *testing.T, c *corpusCase) {
	t.Helper()

	c.requireOut(t)
	patterns := c.patterns()

	// The statement itself. One comparison carries all of it: which text was
	// redacted, what each redaction is attributed to, how many there are, in
	// what order, and that the text around them is the text that went in.
	out, values := maskMarked(patterns, c.in)
	if out != c.out {
		t.Fatalf("%s: masking %q gives\n\t%s\nthe out field says\n\t%s", c.id(), c.in, out, c.out)
	}

	m, err := parseMarked(c.out)
	if err != nil {
		t.Fatalf("%s: the out field is not marked text: %v", c.id(), err)
	}
	restored, err := m.restore(values)
	if err != nil {
		t.Fatalf("%s: %v", c.id(), err)
	}
	if restored != c.in {
		t.Fatalf("%s: the marked text with the values back in it is %q, the in field is %q", c.id(), restored, c.in)
	}

	t.Run("redactors", func(t *testing.T) {
		// One marked text says what every redactor must give, so each is held
		// to it rather than to a line of asterisks written by hand.
		redactors := []struct {
			name     string
			redactor mask.Redactor
			want     string
		}{
			{name: "default", redactor: nil, want: m.fill(values, '*')},
			{name: "Fill('*')", redactor: mask.Fill('*'), want: m.fill(values, '*')},
			{name: "Fill('#')", redactor: mask.Fill('#'), want: m.fill(values, '#')},
			{name: "Fill('●')", redactor: mask.Fill('●'), want: m.fill(values, '●')},
			{name: "Fixed(\"[REDACTED]\")", redactor: mask.Fixed("[REDACTED]"), want: m.fixed("[REDACTED]")},
			{name: "Fixed(\"\")", redactor: mask.Fixed(""), want: m.fixed("")},
			{name: "marking", redactor: markRedactor, want: c.out},
		}

		for _, r := range redactors {
			t.Run(r.name, func(t *testing.T) {
				masker := maskerWith(patterns, r.redactor)
				if got := masker.Mask(c.in); got != r.want {
					t.Fatalf("Mask(%q) = %q, want %q", c.in, got, r.want)
				}
			})
		}
	})

	t.Run("no value survives", func(t *testing.T) {
		// The point of the library: what was redacted is not in the output.
		// Fill leaves as many characters as the value had, so a scan that
		// located all but a byte of a value would pass everything above and
		// fail here.
		//
		// Held only where a value's redaction can be told apart from the value
		// itself: a value already written as "[REDACTED]" reads that way
		// whether Fixed("[REDACTED]") reached it or not, and the same holds a
		// value made of nothing but asterisks against Fill('*'). Where the two
		// differ, finding value in the output still means the redaction left
		// it standing, so the check is not weakened for any value it could
		// tell apart.
		checked := []struct {
			name     string
			redactor mask.Redactor
			redacts  func(value string) string
		}{
			{name: "Fill('*')", redactor: mask.Fill('*'), redacts: func(value string) string {
				return strings.Repeat("*", utf8.RuneCountInString(value))
			}},
			{name: `Fixed("[REDACTED]")`, redactor: mask.Fixed("[REDACTED]"), redacts: func(string) string {
				return "[REDACTED]"
			}},
		}
		for _, r := range checked {
			got := maskerWith(patterns, r.redactor).Mask(c.in)
			for _, value := range values {
				if strings.Count(c.in, value) != 1 {
					continue
				}
				if r.redacts(value) == value {
					continue // this value's own redaction is not distinguishable from it
				}
				if strings.Contains(got, value) {
					t.Errorf("%s: Mask(%q) = %q, which still holds %q", r.name, c.in, got, value)
				}
			}
		}

		// The marking redactor's notation needs no such guard: a corpus in
		// field may not hold "«" or "»" (conformance/CLAUDE.md), so
		// «pattern-name» can never equal a value that came from in.
		got := maskerWith(patterns, markRedactor).Mask(c.in)
		for _, value := range values {
			if strings.Count(c.in, value) == 1 && strings.Contains(got, value) {
				t.Errorf("marking: Mask(%q) = %q, which still holds %q", c.in, got, value)
			}
		}
	})

	t.Run("text around a value", func(t *testing.T) {
		// Everything outside a redaction is the input's own bytes, in order.
		// Fixed("") leaves exactly those.
		got := maskerWith(patterns, mask.Fixed("")).Mask(c.in)
		if want := m.fixed(""); got != want {
			t.Errorf("Mask(%q) = %q, want %q", c.in, got, want)
		}
	})

	t.Run("order of patterns", func(t *testing.T) {
		// Which text is redacted may not depend on the order the patterns were
		// given in; only which pattern a redaction is attributed to may, and
		// the corpus states that with a pair of sets written in either order.
		forward := maskerWith(patterns, mask.Fill('*')).Mask(c.in)
		backward := maskerWith(reversed(patterns), mask.Fill('*')).Mask(c.in)
		if forward != backward {
			t.Errorf("Mask(%q) = %q with the patterns in order and %q reversed", c.in, forward, backward)
		}
	})

	t.Run("options in either order", func(t *testing.T) {
		want := m.fixed("X")
		byPatterns := mask.New(mask.WithPatterns(patterns...), mask.WithRedactor(mask.Fixed("X"))).Mask(c.in)
		byRedactor := mask.New(mask.WithRedactor(mask.Fixed("X")), mask.WithPatterns(patterns...)).Mask(c.in)
		if byPatterns != want || byRedactor != want {
			t.Errorf("Mask(%q) = %q and %q, want %q for both", c.in, byPatterns, byRedactor, want)
		}
	})

	t.Run("split across options", func(t *testing.T) {
		// A set given one pattern at a time through repeated options is the
		// same set.
		opts := make([]mask.Option, 0, len(patterns)+1)
		for _, p := range patterns {
			opts = append(opts, mask.WithPatterns(p))
		}
		opts = append(opts, mask.WithRedactor(mask.Fill('*')))
		if got, want := mask.New(opts...).Mask(c.in), m.fill(values, '*'); got != want {
			t.Errorf("Mask(%q) = %q, want %q", c.in, got, want)
		}
	})

	t.Run("no pattern redacts nothing", func(t *testing.T) {
		if got := mask.New().Mask(c.in); got != c.in {
			t.Errorf("a Masker with no pattern changed %q into %q", c.in, got)
		}
	})

	if !c.reads {
		return
	}

	t.Run("put back together", func(t *testing.T) {
		// The same claim the corpus makes, made again without reading the
		// corpus: mark the redactions with a separator the text does not hold,
		// put the values back, and the input must come out.
		//
		// It holds masking the output to reaching no further than the first
		// pass reached along the way, which is why it sits behind the guard
		// rather than beside the check above. A pattern reporting spans of its
		// own reports the same offsets into text that has changed under them,
		// so a case saying spans: reported is held back from every property
		// that rests on where a value sits.
		checkMasking(t, patterns, c.in)
	})

	t.Run("in a longer text", func(t *testing.T) {
		// A value does not arrive alone. It arrives in a log line, in a line of
		// JSON, in the middle of a paragraph, and what is redacted must be the
		// same wherever it sits. The text put around it is held to being text
		// these patterns find nothing in, so that a case cannot pass here by the
		// surroundings being masked too.
		//
		// A case whose patterns report spans of their own, rather than finding
		// them in the text, says spans: reported: nothing moves for it when the
		// text around it grows.
		affixes := []struct {
			name          string
			before, after string
		}{
			{name: "before", before: "time=2026-08-17T00:00:00Z level=info msg=\"calling api\" ", after: ""},
			{name: "after", before: "", after: " status=200 duration=13ms"},
			{name: "around", before: "log: ", after: " (end)"},
			{name: "on a line of its own", before: "first line\n", after: "\nlast line"},
			{name: "between multi-byte text", before: "日本語 ", after: " 日本語"},
			{name: "directly against multi-byte text", before: "日", after: "語"},
			{name: "between control bytes", before: "\x00", after: "\x00"},
			{name: "between tabs", before: "\t", after: "\t"},
		}

		for _, affix := range affixes {
			t.Run(affix.name, func(t *testing.T) {
				masker := maskerWith(patterns, mask.Fill('*'))
				if got := masker.Mask(affix.before + affix.after); got != affix.before+affix.after {
					t.Fatalf("the text put around the case is not left alone: %q", got)
				}
				src := affix.before + c.in + affix.after
				want := affix.before + m.fill(values, '*') + affix.after
				if got := masker.Mask(src); got != want {
					t.Errorf("Mask(%q) = %q, want %q", src, got, want)
				}
			})
		}
	})

	t.Run("twice over", func(t *testing.T) {
		// The same value twice in one text is redacted twice: a scan that stops
		// at the first, or one whose cursor does not carry past it, shows here.
		masker := maskerWith(patterns, mask.Fill('*'))
		src := c.in + "\n" + c.in
		want := m.fill(values, '*') + "\n" + m.fill(values, '*')
		if got := masker.Mask(src); got != want {
			t.Errorf("Mask(%q) = %q, want %q", src, got, want)
		}
	})
}

// maskerWith returns a Masker over patterns, with redactor where one is given
// and the default otherwise.
func maskerWith(patterns []mask.Pattern, redactor mask.Redactor) *mask.Masker {
	if redactor == nil {
		return mask.New(mask.WithPatterns(patterns...))
	}
	return mask.New(mask.WithPatterns(patterns...), mask.WithRedactor(redactor))
}

func TestConformance_concurrentUse(t *testing.T) {
	// A Masker, a Pattern and a Redactor are all documented safe for concurrent
	// use, and the built-in scans carry a cursor and a decoder as they go.
	// Driving the whole corpus from many goroutines at once puts what they
	// carry under the race detector and holds every answer to the one a single
	// goroutine gets.
	cases := corpusCases(t)
	maskers := make([]*mask.Masker, len(cases))
	for i, c := range cases {
		c.requireOut(t)
		maskers[i] = maskerWith(c.patterns(), markRedactor)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 4 {
				for i, c := range cases {
					if got := maskers[i].Mask(c.in); got != c.out {
						t.Errorf("%s: Mask(%q) = %q, want %q", c.id(), c.in, got, c.out)
						return
					}
				}
			}
		})
	}
	wg.Wait()
}

func TestConformance_oneMaskerForEveryCase(t *testing.T) {
	// A caller builds one Masker and hands it everything, so the corpus is run
	// again through a single Masker over the built-in patterns. Only the cases
	// masked with the built-in set say what must come out; the rest are here
	// because nothing may go wrong when they are handed to it.
	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...), mask.WithRedactor(markRedactor))

	for _, c := range corpusCases(t) {
		c.requireOut(t)
		got := m.Mask(c.in)
		if c.set == "default" && got != c.out {
			t.Errorf("%s: Mask(%q) = %q, want %q", c.id(), c.in, got, c.out)
		}
	}
}

// negativeCaseNames and negativeCaseNameEndings are phrases the corpus
// already uses to say a case locates nothing, in its own name.
// positiveCaseNames is the same for a case that does locate something.
//
// A case name carries the same weight as a comment: conformance/CLAUDE.md
// holds it to naming the rule the scan reads rather than a property of the
// input, and says no out can contradict it. A scan regression that widened or
// narrowed what a case locates leaves the name stating what used to be true,
// and -update rewrites the out field it sits beside without anyone noticing
// the two have come apart.
//
// Every phrase here is verified against the corpus as it stands: grepping
// case names for "is no ", "is not " and their plurals turns up as many that
// name a component of a case that is still located as a whole — "a hyphen
// with no digit behind it is no tail" locates the token beside the hyphen,
// and "an installation token followed by a file name is not drawn into one
// span" locates the token too — as ones that say the whole case locates
// nothing. Contains would read the first kind as a false claim of its own,
// so both are read as endings instead: the corpus's genuine nothing-located
// cases put the predicate at the very end of the name ("... is no key",
// "... is not a token") and name the credential itself there, where a
// component fact names something narrower ("... is no tail") and is not
// read as a claim about the case at all.
var (
	negativeCaseNames = []string{
		"leaves it alone", "left alone", "leaves them alone",
		"finds nothing", "matches nothing", "redacts nothing",
		"is ignored", "are ignored", "is not located", "are not located",
	}
	negativeCaseNameEndings = []string{
		"is no key", "is no token", "is no key of this kind", "is no armor header",
		"is not a token", "is not a key", "is not an access key id",
		"is not one of the kinds this library knows",
	}
	positiveCaseNames = []string{
		"is located", "are located", "is redacted", "are redacted", "is used",
	}
)

func TestCorpus_caseNamesAgreeWithTheirOut(t *testing.T) {
	// out is generated and case names are not, so a name is the one place a
	// claim about a case can drift from what -update just wrote without
	// anything else here reporting it: conformance/CLAUDE.md's own words are
	// "no out line can contradict" a name, which is what this test reads the
	// two against each other to hold.
	//
	// The vocabulary above is deliberately the corpus's own rather than a
	// general-purpose parse of English, so what this catches is a scan
	// regression that changes whether a case locates anything at all —
	// exactly what -update would rewrite silently — and not a name it cannot
	// read confidently either way. A pattern arriving with a case named some
	// other way for "locates nothing" is not reported by this: undercounting
	// is the safe failure here, over-flagging a case that never claimed what
	// the vocabulary reads into it is not.
	cases := corpusCases(t)
	checked := 0
	for _, c := range cases {
		lower := strings.ToLower(c.name)
		names := c.names(t)

		negative := false
		for _, phrase := range negativeCaseNames {
			if strings.Contains(lower, phrase) {
				negative = true
			}
		}
		for _, ending := range negativeCaseNameEndings {
			if strings.HasSuffix(lower, ending) {
				negative = true
			}
		}

		positive := false
		for _, phrase := range positiveCaseNames {
			if strings.Contains(lower, phrase) {
				positive = true
			}
		}

		switch {
		case negative && positive:
			// A name matching both vocabularies claims a case locates
			// something and claims it locates nothing, in the same name —
			// no out field could agree with both halves at once, whichever
			// way the scan comes out. That makes the name the defect
			// rather than the scan, so it is reported here instead of
			// running the two checks below, which would fail exactly one
			// of them no matter what masking the case does. checked does
			// not count this case: it was never held to its out field,
			// only flagged as needing a reword.
			t.Errorf("%s: the name matches both the vocabulary for locating nothing and the vocabulary for locating something — reword it to say only one", c.id())
		case negative:
			if len(names) != 0 {
				t.Errorf("%s: the name says nothing is located, but masking it locates %v", c.id(), names)
			}
			// A name matching two phrases of the same vocabulary counts
			// once here, not twice: checked counts the cases this held to
			// their out field, not the phrases that matched along the way.
			checked++
		case positive:
			if len(names) == 0 {
				t.Errorf("%s: the name says something is located, but masking it locates nothing", c.id())
			}
			checked++
		}
	}
	// checkedFraction is the floor checked is held to, as a fraction of the
	// corpus. Measured against the corpus as it stands — 3583 cases, of which
	// this vocabulary checks 49 — one in two hundred (17) is comfortably
	// under half of that, roughly a third, so rewording a few of the
	// phrases' current holders does not flake this, while a vocabulary that
	// stopped matching nearly everything — the two lists above going stale
	// as the corpus is renamed around them — still falls under it well
	// before reaching zero. checked == 0 alone would let that slide all the
	// way to nothing unnoticed; holding to a fraction of the corpus instead
	// means a shrink is visible long before it gets there.
	const checkedFraction = 200
	if least := len(cases) / checkedFraction; checked < least {
		t.Fatalf("checked %d case name(s) against their out field, want at least %d (%d corpus case(s) / %d) — the vocabulary above may no longer match how the corpus names cases",
			checked, least, len(cases), checkedFraction)
	}
	t.Logf("checked %d case name(s) against their out field", checked)
}

func TestConformance_aPatternGivenTwice(t *testing.T) {
	// WithPatterns: "Repeated options accumulate in the order given." Nothing
	// says what a Pattern given twice — the same instance, once through one
	// option and once through a second, or once through each of two calls to
	// WithPatterns — does to the redaction count or to the attribution. A
	// close analogue is pinned elsewhere (two distinct patterns reporting the
	// same span merge into one redaction, Mask's own doc example), so what is
	// new here is the identical-instance case: it must merge into the one
	// redaction a caller assembling patterns from a list that happened to
	// repeat one would still expect.
	p := mask.GitHubToken()
	const src = "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	const want = "GITHUB_TOKEN=«github-token»"

	variants := []struct {
		name string
		opts []mask.Option
	}{
		{name: "one pattern given once", opts: []mask.Option{mask.WithPatterns(p)}},
		{name: "one pattern given twice in one option", opts: []mask.Option{mask.WithPatterns(p, p)}},
		{name: "one pattern given twice across two options", opts: []mask.Option{mask.WithPatterns(p), mask.WithPatterns(p)}},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			var seen int
			redactor := mask.NewRedactor(func(m mask.Match) string {
				seen++
				return string(markOpen) + m.Pattern.Name() + string(markClose)
			})
			m := mask.New(append(v.opts, mask.WithRedactor(redactor))...)
			if got := m.Mask(src); got != want {
				t.Errorf("Mask(%q) = %q, want %q", src, got, want)
			}
			if seen != 1 {
				t.Errorf("the redactor was called %d time(s), want 1", seen)
			}
		})
	}
}

func TestConformance_regexpAnchor(t *testing.T) {
	// LookBehind names ^ beside \b and \B as what the one rune of context a
	// Pattern built by Regexp reads is decided by. ^ is a poor fit for a
	// corpus case: checkCase's "in a longer text" and "twice over" wrap every
	// case in more text by design, which is exactly the question ^ answers
	// differently once asked of it, so a case built on it would fail
	// properties that hold of every other case for a reason that is not a
	// defect. This states the same rule directly instead.
	p := mask.MustRegexp("line-start", `^TOKEN=[0-9a-f]{8}`)
	m := mask.New(mask.WithPatterns(p), mask.WithRedactor(mask.Fill('*')))

	tests := []struct {
		name string
		src  string
		want string
	}{
		{name: "anchored at the start of the text", src: "TOKEN=0123456789", want: "**************89"},
		{name: "not anchored once something stands in front of it", src: "x TOKEN=01234567", want: "x TOKEN=01234567"},
		{name: "a byte order mark stands in front of the anchor", src: "\xef\xbb\xbfTOKEN=01234567", want: "\xef\xbb\xbfTOKEN=01234567"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func TestConformance_maskingTwiceMayRedactMoreThanOnce(t *testing.T) {
	// Mask's own doc, concretely: "an AWS access key ID written against a
	// Slack prefix is redacted on the first pass and takes a Slack token with
	// it on the second." SlackToken's own doc explains why the first pass
	// stops short: "A prefix written against a letter or a digit opens
	// nothing." AWSAccessKeyID's twenty characters end in a letter or a digit
	// whatever the key, so a Slack prefix written straight against one opens
	// no candidate until that key is replaced — with an asterisk, which is
	// neither.
	m := mask.New(mask.WithPatterns(mask.AWSAccessKeyID(), mask.SlackToken()), mask.WithRedactor(mask.Fill('*')))
	const slackBody = "xoxb-0123456789ab-0123456789abc-0123456789abcdefghijklmn"
	const src = "AKIA0123456789ABCDEF" + slackBody

	once := m.Mask(src)
	if !strings.Contains(once, slackBody) {
		t.Fatalf("Mask(%q) = %q, want the slack-shaped text to survive the first pass, its prefix standing against the letter the AWS key ends in", src, once)
	}
	if got, want := strings.Count(once, "*"), 20; got != want {
		t.Fatalf("Mask(%q) = %q with %d asterisk(s), want %d: the AWS access key ID's twenty characters replaced and nothing else", src, once, got, want)
	}

	twice := m.Mask(once)
	if got, want := strings.Count(twice, "*"), strings.Count(once, "*"); got <= want {
		t.Errorf("masking twice gave %d asterisk(s), masking once gave %d; the asterisks standing where the AWS key was replace a letter and a digit no longer, so the Slack prefix beside them must now open", got, want)
	}
}

func TestConformance_fixedEmptySplicingCanManufactureACredential(t *testing.T) {
	// Mask's own doc: `Fixed("") ... splic[es] the text either side of it
	// into text that was never written." A caller's own pattern can cut a
	// span out of the middle of what will become, once spliced, a value a
	// built-in locates — nothing about that is particular to this library's
	// own patterns overlapping each other, and the doc's warning covers a
	// pattern of a caller's doing it too.
	cut := spansPattern("cut", mask.Span{Start: 3, End: 10})
	const src = "sk_XXXXXXXlive_0123456789abcdef01234567"

	spliced := mask.New(mask.WithPatterns(cut), mask.WithRedactor(mask.Fixed(""))).Mask(src)
	const want = "sk_live_0123456789abcdef01234567"
	if spliced != want {
		t.Fatalf("Mask(%q) = %q, want %q", src, spliced, want)
	}

	// StripeSecretKey's own doc: "A key is located wherever it is written, so
	// long as no letter or digit stands in front of it." Nothing stands in
	// front of the splice at all, so if this text is now shaped like a
	// Stripe secret key it is located — a credential the splice manufactured
	// out of text neither half of which was one on its own.
	again := mask.New(mask.WithPatterns(mask.StripeSecretKey()), mask.WithRedactor(mask.Fill('*'))).Mask(spliced)
	if again == spliced {
		t.Errorf("Mask(%q) = %q, want the spliced text located as a stripe-secret-key", spliced, again)
	}
}

func TestConformance_scale_oneLine(t *testing.T) {
	// TestConformance_scale builds its multi-mebibyte document out of the
	// corpus joined with newlines, which is what a scan whose cost depends on
	// where the newlines fall would pass without ever being asked the
	// question: "A log stream is not a line" holds for the other direction
	// too, and a minified bundle, a single-line JSON body or a stack trace
	// joined with \n escapes is exactly that direction. The same corpus
	// joined with spaces instead states scale over one line rather than over
	// many, following TestConformance_scale's own reasoning for what a value
	// may survive at scale: no more per copy than one properly masked unit
	// already holds of its own raw text.
	const (
		size  = 1 << 20
		limit = 4 * time.Second
	)

	var parts []string
	values := make(map[string]bool)
	for _, c := range corpusCases(t) {
		if strings.ContainsAny(c.in, "\n\r") {
			continue // a line holds neither
		}
		parts = append(parts, c.in)
		_, vs := maskMarked(mask.AllBuiltinPatterns(), c.in)
		for _, v := range vs {
			values[v] = true
		}
	}
	if len(parts) == 0 {
		t.Fatal("no corpus case is free of newlines, so no one line could be built from it")
	}
	unit := strings.Join(parts, " ")
	if unit == "" {
		t.Fatal("the corpus contributed no text at all")
	}
	n := size/len(unit) + 1
	src := strings.Repeat(unit+" ", n)
	if strings.ContainsAny(src, "\n\r") {
		t.Fatal("the line built for this test holds a newline after all")
	}

	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))
	wantUnit := m.Mask(unit)
	start := time.Now()
	masked := m.Mask(src)
	if d := time.Since(start); d > limit {
		t.Errorf("masking %d bytes on one line took %v, want under %v", len(src), d, limit)
	}
	if got, want := utf8.RuneCountInString(masked), utf8.RuneCountInString(src); got != want {
		t.Errorf("masking with Fill left %d runes, the input had %d", got, want)
	}

	// A positive statement that the values in the middle of the huge line
	// were found: a value surviving here more often than one masked copy of
	// the unit already holds it is a value the scan lost once the line grew
	// past whatever bounded it on a shorter input.
	for v := range values {
		if got, want := strings.Count(masked, v), n*strings.Count(wantUnit, v); got > want {
			t.Errorf("the value %q appears %d time(s) in %d copies of the line, want at most %d", v, got, n, want)
		}
	}
}

func TestCorpus_cleanCasesLocateNothingNewAcrossTheRegistry(t *testing.T) {
	// TestCorpus_coversEveryBuiltinPattern asks for cases masked with a set
	// holding one built-in alone, locating nothing, so that a pattern's own
	// near-misses are on the record: a prefix with no body, a body with no
	// prefix, an upper-cased prefix, a body a hyphen breaks. A pattern added
	// later, or a pattern's grammar widened, can turn one of those near-misses
	// into a value some other pattern locates, and the per-pattern corpus
	// never notices: the case is masked with one built-in alone everywhere
	// else it is read, so a second pattern reacting to it is a redaction
	// nothing here compares against.
	//
	// A clean case run through every built-in at once, as a caller who wants
	// them all does, closes that. It is driven from the corpus rather than
	// from a table of samples for the reason `Test_builtins_anchorsAreNotValues`
	// is not enough on its own: the anchors that test holds are short
	// fragments common to the whole registry, where a clean case is built
	// against the one pattern its file is about and is the wider, more varied
	// set of near-misses.
	//
	// It is not zero, and the corpus itself is why. A vendor issuing more than
	// one credential in the one shape a caller cannot always be reading behind
	// one name — Stripe's publishable and secret keys, Supabase's three
	// project keys, Cloudflare's key and its token, AWS's access key ID and
	// its secret — leaves a text that is one pattern's near-miss and another's
	// real value, and a pattern's own file states as much where it does:
	// builtin_aws_access_key_id.txt says outright that its clean cases "show
	// where the boundary between the two falls rather than what a caller
	// holding both would see." JWT and PrivateKey read the same way for a
	// different reason: neither is a vendor's format, both are written wide
	// enough that a placeholder standing in for one in another pattern's
	// clean case is a genuine instance of it, and declining a genuine JWT
	// because it stands beside ghp_ or hvs. would be declining every JWT
	// written beside such a prefix in real text.
	//
	// A collision belonging to neither of those is one two vendors spelled the
	// same way by coincidence, which is a thing to write down where the text
	// that collides can be read: builtins_together.txt states the one this
	// count holds, beside the case that shows it.
	//
	// So the bar this holds to is not zero, and holding it to zero would only
	// have this fail on the corpus as it stands rather than on a registry that
	// changed. It is the count above, held to exactly rather than to a
	// ceiling: a ceiling alone misses the count staying put while one
	// collision it already knew about is replaced by a different one, which
	// is as much a change to the registry as a net increase is. More than
	// knownCollisions says a pattern — added, or widened — now reacts to
	// another pattern's clean text, the finding this property exists for.
	// Fewer says a pattern that used to reach one of these no longer does,
	// which is worth the same look: a grammar someone narrowed on purpose
	// reads as fewer here, and so does one narrowed by accident, taking a
	// value it used to locate with it. Either direction is reviewed the same
	// way — read what the failure lists, decide whether the registry moved on
	// purpose, and set knownCollisions to the count the failure reports.
	const knownCollisions = 40

	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))
	driven := 0
	var found []string
	for _, c := range corpusCases(t) {
		// custom_patterns.txt is masked with MustRegexp, NewPattern or no
		// pattern at all (conformance/CLAUDE.md); a clean case there says a
		// built-in pattern was not asked to look, not that none of them would
		// have found anything, so it states nothing this property could hold.
		if c.file == "custom_patterns.txt" {
			continue
		}
		if len(c.names(t)) > 0 {
			continue // reads something under its own patterns; not a clean case
		}
		driven++
		if got := m.Mask(c.in); got != c.in {
			out, _ := maskMarked(mask.AllBuiltinPatterns(), c.in)
			found = append(found, fmt.Sprintf("%s [set=%s]: clean under %s alone, the whole registry masks %q to %q",
				c.id(), c.set, c.set, c.in, out))
		}
	}

	if driven == 0 {
		t.Fatal("no clean case was driven")
	}
	if collisions := len(found); collisions != knownCollisions {
		// Every collision named on its own line, ahead of the count: a
		// developer reading only the last failure of a run still sees the
		// whole list, rather than one that needs -v to come back.
		for _, line := range found {
			t.Error(line)
		}
		t.Errorf("%d clean case(s) now locate something under the whole registry, knownCollisions says %d — "+
			"review the case(s) above, and if the registry moved on purpose set knownCollisions to %d",
			collisions, knownCollisions, collisions)
	}
	t.Logf("drove %d clean case(s), %d of them located something under the whole registry (knownCollisions=%d)",
		driven, len(found), knownCollisions)
}

func TestCorpus_coversEveryBuiltinPattern(t *testing.T) {
	// The corpus is the statement of what this library does, so a built-in
	// pattern absent from it is a pattern nothing here states anything about.
	// Adding one to AllBuiltinPatterns therefore fails until the corpus says what
	// it locates and what it leaves alone.
	const least = 3

	located := map[string]int{} // cases locating the pattern, however many times
	alone := map[string]int{}   // cases where the pattern by itself locates nothing
	for _, c := range corpusCases(t) {
		names := c.names(t)
		if len(names) > 0 {
			// Cases, not redactions: one line holding two tokens says one
			// thing about the pattern, not two, and counting it twice would
			// leave the bar below met by half the cases it asks for.
			for _, name := range slices.Compact(slices.Sorted(slices.Values(names))) {
				located[name]++
			}
			continue
		}
		// A case that locates nothing counts for a pattern only where that
		// pattern is the whole set it was masked with. The clean cases masked
		// with every built-in at once are inherited by each pattern added to
		// that set, and would meet the bar below without one case having been
		// written about the pattern being added.
		if set := c.patterns(); len(set) == 1 {
			alone[set[0].Name()]++
		}
	}

	for _, p := range mask.AllBuiltinPatterns() {
		t.Run(p.Name(), func(t *testing.T) {
			if located[p.Name()] < least {
				t.Errorf("the corpus has %d case(s) locating a %s, want at least %d", located[p.Name()], p.Name(), least)
			}
			if alone[p.Name()] < least {
				t.Errorf("the corpus has %d case(s) where %s alone locates nothing, want at least %d", alone[p.Name()], p.Name(), least)
			}
		})
	}
}

func TestCorpus_everyBuiltinHasAFileOfItsOwn(t *testing.T) {
	// The cases a pattern is stated by go in a file named for it, which is how
	// a reader finds them and how a reviewer sees at a glance that a pattern
	// arrived with any. Nothing else asks for it: the corpus is loaded by a
	// glob over *.txt, so a file named some other way is read, its cases run
	// and its pattern covered — TestCorpus_coversEveryBuiltinPattern counts
	// cases, not files, and would be satisfied by cases written anywhere at
	// all. The convention would then hold for every pattern but the one added
	// last, and go on looking like a convention.
	//
	// The name is the pattern's own with the hyphens written as underscores,
	// since that is what the rest of the repository does with it: the pattern
	// named aws-access-key-id is declared in builtin_aws_access_key_id.go.
	for _, p := range mask.AllBuiltinPatterns() {
		want := "builtin_" + strings.ReplaceAll(p.Name(), "-", "_") + ".txt"
		t.Run(p.Name(), func(t *testing.T) {
			if _, err := os.Stat(filepath.Join(corpusDir, want)); err != nil {
				t.Errorf("%s has no file of its own: %s", p.Name(), want)
			}
		})
	}
}

// everyKindCase names the case whose name claims to hold one credential of
// every kind the library knows, and the file it is read from.
//
// The file is part of the name here because a case name is unique within its
// file and not across the corpus, as corpusCase.subtest says. Files are read in
// name order, so a case of this name written into any of the builtin_*.txt
// ahead of it would be the one found, and the case this is about could then
// stop naming a pattern with nothing reporting it.
const (
	everyKindFile = "builtins_together.txt"
	everyKindCase = "every kind of credential this library knows"
)

func TestCorpus_everyKindCaseHoldsEveryBuiltin(t *testing.T) {
	// The case named above is the one place the corpus states that the patterns
	// do not interfere with a line holding all of them at once, and its name is
	// a claim about the whole registry rather than about its own text. No out
	// line can contradict that name: a pattern added to the registry and left
	// out of the case leaves the line masked exactly as it was, and the case
	// goes on passing while claiming to cover a pattern it never held. So the
	// count is done here, which is what conformance/CLAUDE.md asks of a comment
	// or a name saying "every".
	var found *corpusCase
	for _, c := range corpusCases(t) {
		if c.file == everyKindFile && c.name == everyKindCase {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatalf("no case named %q in %s: it is what TestCorpus_everyKindCaseHoldsEveryBuiltin counts, so renaming or moving it needs changing here", everyKindCase, everyKindFile)
	}

	located := map[string]bool{}
	for _, name := range found.names(t) {
		located[name] = true
	}
	for _, p := range mask.AllBuiltinPatterns() {
		if !located[p.Name()] {
			t.Errorf("%s: the case locates no %s, which its name says it holds", found.id(), p.Name())
		}
	}
}

func TestCorpus_usesEveryPatternSet(t *testing.T) {
	// A set nothing names is a set nothing is stated with, and reading the
	// corpus would suggest otherwise.
	used := map[string]int{}
	for _, c := range corpusCases(t) {
		used[c.set]++
	}
	for _, name := range slices.Sorted(maps.Keys(patternSets)) {
		if used[name] == 0 {
			t.Errorf("no case is masked with the pattern set %q", name)
		}
	}
}

func TestCorpus_attributionIsExercised(t *testing.T) {
	// overlap_and_attribution.txt states how a redaction is attributed when two
	// patterns cover the same span, and states it with patterns of its own. What
	// it cannot say for itself is whether any built-in input reaches those rules:
	// two built-ins reporting one span is what drives the last of them,
	// registration order, and only the corpus in full can be counted for it.
	//
	// A comment there counts before writing "every", "only" or "no input at all",
	// and this is what a comment about this one rests on. No out line can say it.
	// An out line names the pattern the redaction went to, so it does pin which
	// of two that reach one span won it — but not that a second one reached it at
	// all. Let the losing pattern stop locating that value and the winner wins
	// still, the line stays exactly as it was, and the rule is reached by nothing
	// any more.
	//
	// Each case is read with the set it is masked with rather than with every
	// built-in, because reaching the rule is what is being counted and a case
	// masked with one pattern reaches nothing however its text reads. Moving the
	// case that reaches it under a set of one would otherwise leave this passing
	// on a collision the corpus no longer performs. Only built-ins count towards
	// it: the patterns of overlap_and_attribution.txt are written to cover one
	// span and would meet the bar on their own, which is the arrangement the
	// comment there is drawing a contrast with.
	type span struct{ start, end int }

	builtin := map[mask.Pattern]bool{}
	for _, p := range mask.AllBuiltinPatterns() {
		builtin[p] = true
	}

	var together []string
	for _, c := range corpusCases(t) {
		at := map[span][]string{}
		for _, p := range c.patterns() {
			if !builtin[p] {
				continue
			}
			spans, _ := p.Find(c.in)
			for _, s := range spans {
				// The names, not the spans: a scan reporting one span twice, or
				// a set naming one pattern twice, is one pattern still and
				// reaches no tie-break. Counting the report rather than the
				// pattern would leave this met with nothing contesting anything.
				k := span{s.Start, s.End}
				if !slices.Contains(at[k], p.Name()) {
					at[k] = append(at[k], p.Name())
				}
			}
		}
		for _, k := range slices.SortedFunc(maps.Keys(at), func(a, b span) int {
			if a.start != b.start {
				return cmp.Compare(a.start, b.start)
			}
			return cmp.Compare(a.end, b.end)
		}) {
			// The names are in the order the case's own set holds them, which
			// is the order the tie-break reads: Masker.locate sorts on the
			// index of the pattern in the list it was given. So of two tied
			// here the first is the one the redaction went to — though a third
			// pattern reporting a longer span from the same start would take it
			// from both, which is a different rule and not what this counts.
			if names := at[k]; len(names) > 1 {
				together = append(together, fmt.Sprintf("%s: [%d,%d) %s", c.id(), k.start, k.end, strings.Join(names, ", ")))
			}
		}
	}

	if len(together) == 0 {
		t.Error("no corpus case masks with two built-in patterns reporting one span, so nothing here reaches the tie-break " +
			"in overlap_and_attribution.txt; write a case that does, or say in that file that only its own patterns reach it")
		return
	}
	t.Log("built-in values sharing a span, first name first:\n\t" + strings.Join(together, "\n\t"))
}

func TestCorpus_summary(t *testing.T) {
	// What the corpus covers, in one place, for whoever is reading it rather
	// than running it.
	cases := corpusCases(t)
	byPattern := map[string]int{}
	clean := 0
	for _, c := range cases {
		names := c.names(t)
		if len(names) == 0 {
			clean++
		}
		for _, name := range names {
			byPattern[name]++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d cases, %d of which hold no value", len(cases), clean)
	for _, name := range slices.Sorted(maps.Keys(byPattern)) {
		fmt.Fprintf(&b, "\n\t%s: %d redaction(s)", name, byPattern[name])
	}
	t.Log(b.String())
}

func TestConformance_aCaseIsAtLeastOneKibibyteLong(t *testing.T) {
	// TestConformance_scale states correctness at the scale of the whole
	// corpus repeated; nothing states that a single case, on its own, is
	// realistic key-material size — a PEM-encoded RSA key or a JWT with a
	// real payload runs to kilobytes in one value. "a jwt with a large
	// payload" (text_shapes.txt) is written to be that case; this counts
	// rather than trusts it, so a rewrite that shortened it back down to a
	// placeholder-sized value would be caught here rather than nowhere.
	const want = 1024

	longest := 0
	for _, c := range corpusCases(t) {
		longest = max(longest, len(c.in))
	}
	if longest < want {
		t.Errorf("the longest case in the corpus is %d byte(s), want at least %d", longest, want)
	}
}

func TestConformance_scale(t *testing.T) {
	// A log stream is not a line. The whole corpus is written into one document
	// of a few mebibytes and masked in one call, which a scan that costs time
	// quadratic in the length of its input does not finish, and which holds the
	// merge and the walk to what they do at size.
	//
	// Fill writes one rune for one rune whether or not anything was found, so
	// the rune count alone says nothing about whether masking happened at all —
	// a Masker given no patterns leaves it unchanged too. What says masking
	// happened is asterisks, counted two ways: against the same corpus masked
	// once and multiplied by how many times it was repeated, since nothing in a
	// wider input turns a value this scan locates on its own into one it does
	// not; and against the values themselves, since a count can rise by the
	// right amount while every asterisk in it stands somewhere other than where
	// a value was.
	//
	// A value is held to surviving no more often at scale than it does once,
	// not to surviving nowhere at all. The corpus builds its values from one
	// ordered run of characters, and more than one case is built to share a
	// run of that alphabet on purpose — builtin_aws_secret_access_key.txt pairs
	// a case whose name and assignment make its forty characters a value with
	// cases holding the same forty behind no name at all, a git commit reads
	// them the same way, and both belong in the one corpus. What is masked
	// once therefore already carries the value's own raw text wherever a case
	// says it must, and that count, not zero, is what n copies of the corpus
	// may not exceed per copy: more occurrences of a value's raw text than one
	// properly masked unit already has is the scan losing at scale what it
	// caught on its own.
	const (
		size  = 2 << 20
		limit = 4 * time.Second
	)

	var b strings.Builder
	// values is what the built-in patterns locate in each case on its own,
	// gathered before the corpus is repeated into src so that widening it
	// cannot be what changes one. A case whose patterns locate nothing in it —
	// prose, a case naming no built-in, a look-alike this library declines —
	// contributes none, and the check below asks nothing of it either.
	values := make(map[string]bool)
	for _, c := range corpusCases(t) {
		b.WriteString(c.in)
		b.WriteString("\n")
		_, vs := maskMarked(mask.AllBuiltinPatterns(), c.in)
		for _, v := range vs {
			values[v] = true
		}
	}
	unit := b.String()
	if unit == "" {
		t.Fatal("the corpus is empty")
	}
	n := size/len(unit) + 1
	src := strings.Repeat(unit, n)

	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))
	wantUnit := m.Mask(unit)
	start := time.Now()
	masked := m.Mask(src)
	if d := time.Since(start); d > limit {
		t.Errorf("masking %d bytes took %v, want under %v", len(src), d, limit)
	}
	if got, want := utf8.RuneCountInString(masked), utf8.RuneCountInString(src); got != want {
		t.Errorf("masking with Fill left %d runes, the input had %d", got, want)
	}
	if got, want := strings.Count(masked, "*"), n*strings.Count(wantUnit, "*"); got < want {
		t.Errorf("masking %d copies of the corpus left %d asterisk(s), want at least %d (%d per copy)", n, got, want, strings.Count(wantUnit, "*"))
	}
	for v := range values {
		if got, want := strings.Count(masked, v), n*strings.Count(wantUnit, v); got > want {
			t.Errorf("the value %q appears %d time(s) in %d copies of the corpus, want at most %d", v, got, n, want)
		}
	}

	// Masking again may redact more than masking once did, which the root
	// package states. What it may not do is redact less: Fill writes a rune for
	// a rune, so a run of asterisks may grow but no asterisk may turn back into
	// text.
	again := m.Mask(masked)
	if got, want := utf8.RuneCountInString(again), utf8.RuneCountInString(masked); got != want {
		t.Errorf("masking a masked document left %d runes, it had %d", got, want)
	}
	if got, want := strings.Count(again, "*"), strings.Count(masked, "*"); got < want {
		t.Errorf("masking a masked document left %d asterisk(s), it had %d", got, want)
	}
}
