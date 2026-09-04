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
	return mask.NewPattern(name, func(src string) ([]mask.Span, int) {
		if want == "" {
			return nil, len(src)
		}
		// What is located is one fixed width, so an occurrence beginning
		// more than a width in front of the end of src is written out in
		// full here whatever follows src.
		retain := max(0, len(src)-len(want)+1)
		var spans []mask.Span
		for i := 0; ; {
			j := strings.Index(src[i:], want)
			if j < 0 {
				return spans, retain
			}
			spans = append(spans, mask.Span{Start: i + j, End: i + j + len(want)})
			// One byte past where this occurrence began, not past where it
			// ended: an occurrence standing inside another is an occurrence,
			// and a scan resuming past the match would step over it and would
			// answer differently for having been shown more of the text in
			// front of it.
			i += j + 1
		}
	})
}

// spansPattern returns a Pattern reporting name that reports spans whatever it
// is handed. A case using one is written against a fixed input, named in the
// case beside it.
func spansPattern(name string, spans ...mask.Span) mask.Pattern {
	return mask.NewPattern(name, func(src string) ([]mask.Span, int) { return spans, len(src) })
}

// retainsNothingPattern returns a Pattern locating every occurrence of want,
// like substringPattern, except that it reports retain as 0 always — the
// naive Find the package docs show a caller writing without a stream in mind,
// which never says any of src is settled.
func retainsNothingPattern(name, want string) mask.Pattern {
	return mask.NewPattern(name, func(src string) ([]mask.Span, int) {
		var spans []mask.Span
		for i := 0; ; {
			j := strings.Index(src[i:], want)
			if j < 0 {
				return spans, 0
			}
			spans = append(spans, mask.Span{Start: i + j, End: i + j + len(want)})
			i += j + 1
		}
	})
}

// hostileSpans is a pattern reporting spans a caller's Pattern is under no
// obligation to be careful about: empty, reversed, negative, past the end of
// src, duplicated, and dependent on len(src) in a way the merge has to
// survive. FuzzMask_customPatterns drives generated text through it beside
// the built-ins, so that the hostile-span contract Masker.Mask states is
// fuzzed at the merge rather than pinned only on the two fixed inputs
// mask_test.go carries in the root package.
var hostileSpans = mask.NewPattern("hostile", func(src string) ([]mask.Span, int) {
	n := len(src)
	return []mask.Span{
		{Start: n / 2, End: n + 5},
		{Start: -1, End: 2},
		{Start: n / 3, End: n / 3},
		{Start: n, End: 0},
		{Start: 1, End: 2},
		{Start: 1, End: 2},
	}, 0
})

// patternSets is what the patterns field of a case names.
//
// A case that names none is masked with what the last patterns directive above
// it named, and with "default" only where no directive stands above it — the
// built-in patterns as AllBuiltinPatterns reports them, which is how the
// library is used. The name is the notation's, for the set a case falls back
// to, and says nothing about which patterns a caller ought to reach for.
//
// The set holding one built-in and nothing else is not written here for any of
// them. Every built-in gets one, named as the pattern names itself, derived
// from AllBuiltinPatterns below — as builtinSets (properties_test.go) already
// is. Writing them out would state a third time what builtins.go states and
// what builtinPatterns (builtins_test.go) is held to restate, and a name long
// enough to widen the column would rewrite every line beside it; neither buys a
// disagreement anything could report.
var patternSets = func() map[string][]mask.Pattern {
	sets := make(map[string][]mask.Pattern, len(customPatternSets)+len(mask.AllBuiltinPatterns()))
	for _, p := range mask.AllBuiltinPatterns() {
		sets[p.Name()] = []mask.Pattern{p}
	}
	maps.Copy(sets, customPatternSets)
	return sets
}()

// customPatternSets is every set that is not one built-in on its own: the whole
// registry, the patterns this file builds, and the sets stating how spans are
// resolved.
//
// It is kept apart from patternSets rather than written into it so that
// Test_patternSets_nameNoBuiltinTwice can ask whether a name here also names a
// built-in. Merged into one literal, such a collision would quietly replace the
// set a corpus case meant with the other, and every case naming it would go on
// passing against the wrong patterns.
var customPatternSets = map[string][]mask.Pattern{
	// Every built-in at once, which is what says the sets do not interfere.
	// What each locates on its own is said by the set derived above.
	"default": mask.AllBuiltinPatterns(),

	// No pattern at all: a Masker given none redacts nothing.
	"none": {},

	// The patterns a caller builds.
	"regexp":            {mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`)},
	"regexp-mask-group": {mask.MustRegexp("user-id", `user_id=(?P<mask>\d+)`)},
	// A marker written in variants is one alternation with the group named in
	// each branch, which Go admits and MustRegexp reads all of.
	"regexp-mask-group-branches": {mask.MustRegexp("key", `key_(?:live_(?P<mask>[0-9a-f]+)|test_(?P<mask>[0-9a-f]+))`)},
	"func":                       {substringPattern("shared-secret", "0123456789abcdef0123456789abcdef")},
	"default-and-regexp": append(
		mask.AllBuiltinPatterns(),
		mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`),
	),

	// A pattern that never settles anything, which is what a Find written
	// without a stream in mind returns per the package docs. Mask ignores
	// retain outright, so nothing here should differ from a pattern that
	// settles the ordinary way; what would differ is a stream, which
	// unusable_spans.txt's sibling below drives.
	"func-retains-nothing": {retainsNothingPattern("naive", "0123456789abcdef0123456789abcdef")},

	// The one span shape Pattern.Find documents as neither ignored nor
	// repaired: a span whose end falls inside a multi-byte rune. Written
	// against "日本" (two three-byte runes) rather than against "abcdef" as
	// the rest of unusable_spans.txt is, since a rune has to stand there for
	// the span to cut in half.
	"span-inside-a-rune": {spansPattern("half", mask.Span{Start: 0, End: 1})},

	// \b, a word boundary — one of the two things LookBehind names as why a
	// Pattern built by Regexp reads one rune of context, the other being ^,
	// which is not a corpus case of its own for the reason
	// TestConformance_regexpAnchor (conformance_test.go) gives: checkCase's
	// "in a longer text" and "twice over" wrap every case in more text by
	// design, exactly the question ^ answers differently once asked of it, so
	// it states the rule directly instead. Neither is exercised by the
	// "regexp" set above, which opens on a literal alone.
	"regexp-bounded": {mask.MustRegexp("bounded", `\bINT-[0-9a-f]{32}\b`)},

	// A regular expression whose whole match can be empty. Go's regexp
	// reports an empty match at nearly every position of text holding none of
	// x, and Pattern.Find's own contract says a span whose Start is not less
	// than its End is ignored — this is what states that the ignored spans
	// Go's engine hands back this way are what "ignored" means here, not a
	// crash and not a redaction of a place nothing was written.
	"regexp-empty": {mask.MustRegexp("maybe", `x*`)},

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

func Test_patternSets_nameNoBuiltinTwice(t *testing.T) {
	// Every built-in has a set holding it and nothing else, which a case names
	// to state what that pattern locates on its own and which the clean cases
	// TestCorpus_coversEveryBuiltinPattern counts are masked with. Those sets
	// are derived, so what can go wrong is not a missing one but a name written
	// into customPatternSets that a built-in already answers to: the merge would
	// hand that name to the hand-written set and every case naming it would go
	// on passing against patterns the case never meant.
	for _, p := range mask.AllBuiltinPatterns() {
		if _, ok := customPatternSets[p.Name()]; ok {
			t.Errorf("customPatternSets names %q, which is what the built-in of that name is derived under", p.Name())
		}
	}
}

func Test_substringPattern_emptyWant(t *testing.T) {
	if spans, _ := substringPattern("empty", "").Find("abcdef"); len(spans) != 0 {
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
