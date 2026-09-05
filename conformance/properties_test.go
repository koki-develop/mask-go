// What must hold of masking any text at all.
//
// The corpus states exactly what each of its cases masks to. That is what makes
// it reviewable, and it is also its limit: it says nothing about the text nobody
// wrote down. The properties here take the corpus as a starting point and drive
// the library through text derived from it — the prefixes and suffixes of every
// case, a byte pushed into the interesting positions of one, cases run together
// — holding each result not to an expectation written by hand but to what must
// be true of any masking whatsoever.
//
// Which offsets of a case those are is offsetsDriven's, and it is fewer under
// the race detector than without it.

package conformance

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/koki-develop/mask-go"
)

// separatorFor returns a byte that does not occur in src, which lets what was
// redacted be told from what was not without a notation the text could hold
// itself.
//
// It is one byte or nothing. A separator of two bytes would seem to extend the
// reach to text holding all 256 of them, but it does not: two bytes absent as a
// pair can still be made by the byte before the separator and the first byte of
// it, so splitting on it would find a separator that was never written. Text
// holding every byte there is has nothing to mark it with, and the caller has
// nothing to check.
func separatorFor(src string) (string, bool) {
	var held [256]bool
	for i := range len(src) {
		held[src[i]] = true
	}
	for b := range 256 {
		if !held[b] {
			return string([]byte{byte(b)}), true
		}
	}
	return "", false
}

// checkMasking holds masking src to what must hold of masking anything.
//
// Nothing here compares against a second implementation of the library. What is
// compared against is src itself: a redactor that writes a separator the text
// does not hold marks where each redaction went, and the values it was handed
// put back into those places must give src again. A redaction that ate a byte
// of the text around it, that was reported over text that was never there, or
// that left part of a value behind then has nowhere to hide.
func checkMasking(t testing.TB, patterns []mask.Pattern, src string) {
	t.Helper()

	newMasking(patterns).check(t, src)
}

// masking is checkMasking with what depends on the patterns alone worked out
// once: the Maskers it drives and the set it holds an attribution against.
//
// A property drives one set of patterns over all the text it derives from the
// corpus, and where that is a byte pushed into every position of every case it
// comes to over a million texts. Built inside such a loop, three Maskers and a
// map holding every pattern of the set are more of the work than the masking
// they are there to check. A caller building one and handing it everything is
// also what TestProperties_maskerIsReusable holds a Masker to.
//
// One masks one text at a time, and never two at once: the redactors read the
// call in progress off it, and two texts marked together would be two calls
// with one place to put them. A property below builds one in the subtest a
// pattern set gets, and drives it from there and from the subtests that
// subtest runs in turn — which are subtests it waits for one after another,
// and which adding t.Parallel to would be the two calls this cannot have.
type masking struct {
	known map[mask.Pattern]bool

	marked   *mask.Masker
	fill     *mask.Masker
	remarked *mask.Masker

	// The call in progress. t and src are what a failure is reported against,
	// and the rest is what the redactors are given and what they leave behind.
	t         testing.TB
	src       string
	sep       string
	values    []string
	secondSep string
	found     []string
}

// newMasking returns a masking over patterns.
func newMasking(patterns []mask.Pattern) *masking {
	ms := &masking{known: make(map[mask.Pattern]bool, len(patterns))}
	for _, p := range patterns {
		ms.known[p] = true
	}
	ms.marked = mask.New(mask.WithPatterns(patterns...), mask.WithRedactor(mask.NewRedactor(ms.mark)))
	ms.fill = maskerWith(patterns, mask.Fill('*'))
	ms.remarked = mask.New(mask.WithPatterns(patterns...), mask.WithRedactor(mask.NewRedactor(ms.remark)))
	return ms
}

// mark records what the first pass located and writes the separator where it
// stood.
func (ms *masking) mark(m mask.Match) string {
	ms.values = append(ms.values, m.Value)
	if m.Value == "" {
		ms.t.Fatalf("masking %q redacted nothing at all in one region", ms.src)
	}
	if !ms.known[m.Pattern] {
		ms.t.Fatalf("masking %q attributed a value to a pattern the masker was not given", ms.src)
	}
	return ms.sep
}

// remark records what the second pass located and writes the separator where it
// stood.
func (ms *masking) remark(m mask.Match) string {
	ms.found = append(ms.found, m.Value)
	return ms.secondSep
}

// reportsARuneCuttingSpan reports whether any pattern ms was built with
// reports a usable span over src whose Start or End falls short of a UTF-8
// rune boundary: the one span shape Pattern.Find documents as neither
// ignored nor repaired, so that what stands either side of it is written back
// as found and the output need not be valid UTF-8.
//
// It puts the same question to each pattern's Find that Mask itself puts to
// build masked, rather than naming which pattern might answer yes: a built-in
// and Regexp cannot, by what Find documents of them, but a pattern built by
// hand — hostileSpans, or the one customPatternSets' "span-inside-a-rune"
// states — is free to.
func (ms *masking) reportsARuneCuttingSpan(src string) bool {
	for p := range ms.known {
		spans, _ := p.Find(src)
		for _, s := range spans {
			if s.Start < 0 || s.End > len(src) || s.Start >= s.End {
				continue // Find documents these as ignored rather than used
			}
			if !utf8.RuneStart(src[s.Start]) {
				return true
			}
			if s.End < len(src) && !utf8.RuneStart(src[s.End]) {
				return true
			}
		}
	}
	return false
}

// check holds masking src to what must hold of masking anything, as
// checkMasking states it.
func (ms *masking) check(t testing.TB, src string) {
	t.Helper()

	sep, ok := separatorFor(src)
	if !ok {
		ms.checkAllBytes(t, src)
		return // text holding every byte there is; nothing can mark it
	}

	ms.t, ms.src, ms.sep = t, src, sep
	ms.values = ms.values[:0]
	marked := ms.marked.Mask(src)
	values := ms.values

	kept := strings.Split(marked, sep)
	if len(kept) != len(values)+1 {
		t.Fatalf("masking %q redacted %d value(s) but marked %d place(s)", src, len(values), len(kept)-1)
	}
	var b strings.Builder
	for i, value := range values {
		b.WriteString(kept[i])
		b.WriteString(value)
	}
	b.WriteString(kept[len(kept)-1])
	if b.String() != src {
		t.Fatalf("masking %q gave redactions and text that put back together are %q", src, b.String())
	}

	// What every other redactor writes goes in the same places. Fill is the one
	// that says how much was redacted, so it is the one held to the values.
	var want strings.Builder
	for i, value := range values {
		want.WriteString(kept[i])
		want.WriteString(strings.Repeat("*", utf8.RuneCountInString(value)))
	}
	want.WriteString(kept[len(kept)-1])

	masked := ms.fill.Mask(src)
	if masked != want.String() {
		t.Fatalf("masking %q gave %q, want %q", src, masked, want.String())
	}
	// The built-in patterns and Regexp cannot report a span cutting a
	// multi-byte rune in half — every built-in decides its ends on an ASCII
	// alphabet, and Go's regexp matches runes — so valid UTF-8 in must give
	// valid UTF-8 out wherever nothing driven here actually reports one of
	// those over src. A pattern built by hand, such as hostileSpans or the
	// one span-inside-a-rune states, is free to report one, and
	// reportsARuneCuttingSpan asks Find itself rather than naming which
	// pattern might: the same question Mask puts to it to build masked.
	//
	// !utf8.ValidString(masked) stands last rather than in the middle: it is
	// false on nearly every call, where reportsARuneCuttingSpan calls Find
	// again for every pattern in the set, bypassing the gram prefilter Mask
	// itself reads first. Putting the cheap, almost-always-false check first
	// lets it short-circuit the expensive one on nearly every call instead of
	// paying for it every time.
	if utf8.ValidString(src) && !utf8.ValidString(masked) && !ms.reportsARuneCuttingSpan(src) {
		t.Fatalf("masking valid UTF-8 %q gave %q, which is not valid UTF-8", src, masked)
	}
	ms.checkSecondPass(src, masked, kept, values)
	// A value that was in the text once and has been redacted is not in the
	// output at all. Where it was there more than once, some of them may have
	// been left on purpose — a pattern locating a single letter says nothing
	// about the other letters like it — so only the values that were there once
	// say anything here.
	//
	// What this catches on its own is little, and the guard is why it is worth
	// saying so: masked has just been held to kept and the values, and kept is
	// src with the redactions taken out of it, so a value standing in the
	// output is a value standing in a stretch the first pass left alone. On a
	// repeated input the guard is false throughout and this runs on nothing at
	// all. The property that reaches a scan which located one of two identical
	// values is checkSecondPass, run just above, which reads where the second
	// pass redacts rather than what the first pass left.
	//
	// It reaches that scan where something stands between the two. Where
	// nothing does, the second value begins exactly where the redaction of the
	// first ends, and checkSecondPass reads a value standing against a
	// redaction as one the redaction may have opened — which conformance's
	// CLAUDE.md gives the reason for, and which is the same reading whether the
	// scan lost the value or never could have located it.
	//
	// So values written with nothing at all between them are held by neither
	// property here. What that leaves unreported is a scan which locates the
	// first of a run of them and none of the rest, which is a defect a scan can
	// have: the Stripe keys had it, their bodies being written in the
	// characters a key may not be written after, until the scans were given
	// what tells a key written against a key from one written inside a word.
	//
	// What holds a run of them now is a case rather than a property.
	// builtin_stripe_secret_key.txt states two written together and three, and
	// what those out lines are for is that a scan losing the tail of a run
	// again shows up there.
	//
	// The property is stated only where value's redaction under Fill('*') —
	// as many asterisks as it has runes — can be told apart from value itself.
	// A pattern a caller writes may report any span at all (hostileSpans is
	// one), so a fuzzed value can come out as a run of nothing but '*': "o*"
	// with the pattern above locates "*" alone, one byte, and Fill('*') redacts
	// one byte of it to one asterisk — the same byte. masked then holds "*"
	// exactly where the redaction went, and strings.Contains reading that as
	// the value surviving is reading the redaction, not a defect. Where the
	// two differ, finding value in masked still means the first pass left it
	// standing, so the check is not weakened for any value it could tell apart.
	for _, value := range values {
		if strings.Count(src, value) != 1 {
			continue
		}
		if value == strings.Repeat("*", utf8.RuneCountInString(value)) {
			continue // this value's own redaction is not distinguishable from it
		}
		if strings.Contains(masked, value) {
			t.Fatalf("masking %q gave %q, which still holds the redacted %q", src, masked, value)
		}
	}
}

// checkAllBytes holds masking src, text holding every one of the 256 byte
// values there is, to what can still be said of it once separatorFor has
// nothing left to mark redactions with: check returns without checking
// anything on such an input, so this is what stands in its place rather than
// a silent pass.
//
// Nothing here assumes a value is located at all — a set of one narrow
// pattern may find nothing in 256 bytes drawn from everywhere — so what is
// asked holds whether or not anything was: a value a redactor recorded is
// honestly a substring of src, the text Fixed("") left is what remained once
// every recorded value's bytes were taken out in order, and Fill's rune count
// agrees with what the kept stretches and the recorded values each hold
// counted on their own.
func (ms *masking) checkAllBytes(t testing.TB, src string) {
	t.Helper()

	patterns := make([]mask.Pattern, 0, len(ms.known))
	for p := range ms.known {
		patterns = append(patterns, p)
	}

	var recorded []string
	dropped := mask.New(mask.WithPatterns(patterns...), mask.WithRedactor(mask.NewRedactor(func(m mask.Match) string {
		recorded = append(recorded, m.Value)
		return ""
	}))).Mask(src)
	fill := maskerWith(patterns, mask.Fill('*')).Mask(src)

	total := len(dropped)
	for _, v := range recorded {
		if v == "" {
			t.Fatalf("masking %q recorded an empty value", src)
		}
		if !strings.Contains(src, v) {
			t.Fatalf("masking %q recorded %q, which is not a substring of the input", src, v)
		}
		total += len(v)
	}
	if total != len(src) {
		t.Fatalf("masking %q left %d dropped byte(s) and recorded %d value byte(s), which do not add up to the input's %d bytes",
			src, len(dropped), total-len(dropped), len(src))
	}
	if !isSubsequence(dropped, src) {
		t.Fatalf("masking %q with Fixed(\"\") gave %q, which is not what removing bytes from the input in order would leave", src, dropped)
	}

	// wantRunes is what Fill must leave: the kept stretches' runes plus the
	// recorded values' runes, each counted the way it stood on its own in
	// src. dropped does not keep them apart to count them that way — Fixed("")
	// writes the kept stretches straight into one another with nothing
	// between them — and a rune Fixed("") cut in half can fuse with the byte
	// that now follows it, or a byte it left dangling can decode differently
	// than it would have on its own, so RuneCountInString(dropped) is not
	// their sum.
	//
	// isolated marks the same joins with \xff instead of dropping them.
	// \xff is never a lead byte or a continuation byte of a rune, so
	// splicing it between two stretches of src can never fuse with a byte on
	// either side of it: what stood on either side decodes exactly as it did
	// in src, whether that byte belonged to a stretch this scan cut apart or
	// was already sitting next to a stray 0xff of the input's own. \xff
	// itself always decodes as one rune of its own, so subtracting one rune
	// per join undoes exactly what inserting it added, leaving the kept
	// stretches' runes with nothing else mixed in.
	isolated := mask.New(mask.WithPatterns(patterns...), mask.WithRedactor(mask.NewRedactor(func(mask.Match) string {
		return "\xff"
	}))).Mask(src)
	wantRunes := utf8.RuneCountInString(isolated) - len(recorded)
	for _, v := range recorded {
		wantRunes += utf8.RuneCountInString(v)
	}
	if got := utf8.RuneCountInString(fill); got != wantRunes {
		t.Fatalf("masking %q with Fill left %d rune(s), want %d", src, got, wantRunes)
	}
}

// isSubsequence reports whether every byte of sub appears in s in order, not
// necessarily contiguous — what is left of s once some stretches, in order,
// are taken out of it.
func isSubsequence(sub, s string) bool {
	i := 0
	for j := 0; i < len(sub) && j < len(s); j++ {
		if sub[i] == s[j] {
			i++
		}
	}
	return i == len(sub)
}

// checkSecondPass holds masking masked, which is what masking src gave, to
// redacting only where the first pass reached.
//
// Masking is not idempotent and the root package says so: a redaction reads
// differently from the value it replaced, so it can open a prefix that value
// closed, and an AWS access key ID written against a Slack prefix takes a Slack
// token with it on the second pass. What survives that is not whether the
// second pass redacts but where it may. masked is src with each of values
// replaced by a run of asterisks and kept are the stretches of src between
// them, so where the first pass wrote is known exactly, and a value the second
// pass locates must either overlap one of those runs or stand against one — a
// redaction beside it is what changed how it reads.
//
// A value that does neither is the defect this is here for. It sits in text the
// first pass left as it found it, with the bytes either side of it the ones it
// was written with, so nothing about it had changed when the first pass read
// over it and declined to locate it: a scan whose cursor carried past a value,
// or one that stopped at the first of two.
func (ms *masking) checkSecondPass(src, masked string, kept, values []string) {
	t := ms.t
	t.Helper()

	// Where the first pass wrote, in the offsets of masked. Fill writes one
	// asterisk per rune, which is what the run lengths come from.
	type run struct{ start, end int }
	runs := make([]run, 0, len(values))
	at := 0
	for i, value := range values {
		at += len(kept[i])
		end := at + utf8.RuneCountInString(value)
		runs = append(runs, run{start: at, end: end})
		at = end
	}

	sep, ok := separatorFor(masked)
	if !ok {
		return // text holding every byte there is; nothing can mark it
	}
	ms.secondSep = sep
	ms.found = ms.found[:0]
	remarked := ms.remarked.Mask(masked)
	found := ms.found
	if len(found) == 0 {
		return
	}

	between := strings.Split(remarked, sep)
	if len(between) != len(found)+1 {
		t.Fatalf("masking %q redacted %d value(s) but marked %d place(s)", masked, len(found), len(between)-1)
	}
	at = 0
	for i, value := range found {
		at += len(between[i])
		start, end := at, at+len(value)
		at = end

		// start <= r.end and r.start <= end is overlapping or touching: a
		// value ending where a run begins, or beginning where one ends, has a
		// redaction for a neighbour.
		if slices.ContainsFunc(runs, func(r run) bool { return start <= r.end && r.start <= end }) {
			continue
		}
		t.Fatalf("masking %q gave %q, in which %q is located again at %d, with no redaction of the first pass beside it", src, masked, value, start)
	}
}

// namedSet is a pattern set under the name a failure reports it by.
type namedSet struct {
	name     string
	patterns []mask.Pattern
}

// builtinSets is what the properties are driven with: the built-in patterns
// together, and each of them on its own.
//
// It is derived from AllBuiltinPatterns rather than written out, so that a pattern
// added to the library is driven through every property below without anyone
// remembering to add it here. A set of one is what says a pattern locates a
// value on its own; inside the whole set another pattern's match can cover for
// a defect.
//
// The sets a case builds out of substrings and reported spans are not here:
// they say what they say about the cases they were written for and nothing
// about text derived from them.
//
// A set is also the unit the properties below are run in parallel by: each of
// them drives the whole corpus through every set, so a set is a subtest of its
// own with the case loop inside it. Going parallel a case deep instead would
// divide the same work into as many subtests as there are cases times sets,
// and a parallel subtest is a goroutine and a testing.T held until the test
// around it finishes — tens of thousands of each, where the sets on their own
// already come to more subtests than a runner has cores. The set of every
// built-in is the longest of them, scanning with what each of the others
// scans with, and is a fraction of what they come to together rather than a
// tail the rest wait on.
//
// Nothing a subtest is handed is written to by anything. A set is built here
// and read from then on, WithPatterns copies what it is given into the Masker
// each subtest makes for itself, and the patterns are held safe for concurrent
// use by TestConformance_concurrentUse and, in the root package, by
// Test_builtins_concurrentUse.
var builtinSets = func() []namedSet {
	sets := []namedSet{{name: "default", patterns: mask.AllBuiltinPatterns()}}
	for _, p := range mask.AllBuiltinPatterns() {
		sets = append(sets, namedSet{name: p.Name(), patterns: []mask.Pattern{p}})
	}
	return sets
}()

// readableCases returns the cases whose patterns look at the text they are
// handed, which are the ones text derived from them says anything about.
func readableCases(t testing.TB) []*corpusCase {
	t.Helper()

	var cases []*corpusCase
	for _, c := range corpusCases(t) {
		if c.reads {
			cases = append(cases, c)
		}
	}
	return cases
}

// boundsUnder returns where the values patterns locates in src stand.
//
// It masks rather than reading a case's out field, so it needs no -update to
// have been run and can be asked about a set the case was never written for.
func boundsUnder(t testing.TB, id, src string, patterns []mask.Pattern) [][2]int {
	t.Helper()

	out, values := maskMarked(patterns, src)
	m, err := parseMarked(out)
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	b, err := m.bounds(values)
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	return b
}

// caseBounds returns, for each of cases, where a value stands in its in field:
// under the patterns the case is masked with, and under every built-in.
//
// Both, because the properties reading these drive a case through every
// built-in set and not only through its own. A case written for one pattern may
// hold a value another locates — an AWS secret access key written into a case
// for the access key ID, a JOSE header behind a 1Password prefix — and where
// those values begin and end is exactly what such a property exists to reach.
// Taking the case's own set alone would aim the offsets at the one set the
// property is not about — and it is the faster of the two, so it is what
// someone reading this for speed will reach for.
// TestProperties_offsetsDrivenReachesWhatItIsFor is what fails then.
//
// Asking the whole registry costs one masking pass over the corpus; asking each
// set would cost one per set.
func caseBounds(t testing.TB, cases []*corpusCase) [][][2]int {
	t.Helper()

	builtins := mask.AllBuiltinPatterns()
	bounds := make([][][2]int, len(cases))
	for i, c := range cases {
		own := boundsUnder(t, c.id(), c.in, c.patterns())
		bounds[i] = append(own, boundsUnder(t, c.id(), c.in, builtins)...)
	}
	return bounds
}

func TestProperties_offsetsDrivenReachesWhatItIsFor(t *testing.T) {
	// The two things offsetsDriven does that cost time, held to still being
	// reached by the corpus. Both look like waste to someone reading this
	// package for speed, and both are one line to undo: caseBounds could take
	// the case's own patterns alone, and a case holding no value could be held
	// to the stride like any other. Either would be faster and neither would
	// fail anything else here. This is what fails.
	//
	// It counts rather than asserting a number, for the reason
	// TestCorpus_attributionIsExercised counts: what is at stake is whether the
	// corpus still reaches the rule, and a number written into a comment goes
	// stale the next time the corpus grows while saying nothing when it does.
	cases := readableCases(t)
	builtins := mask.AllBuiltinPatterns()

	var crossPattern, noValue []string
	for _, c := range cases {
		own := boundsUnder(t, c.id(), c.in, c.patterns())
		all := boundsUnder(t, c.id(), c.in, builtins)

		if len(own) == 0 && len(all) == 0 {
			noValue = append(noValue, c.id())
			continue
		}

		// Whether the registry's edges reach an offset the case's own do not,
		// which is what taking the case's own patterns alone would lose.
		kept := make(map[int]bool)
		for _, i := range offsetsWorthDriving(c.in, own) {
			kept[i] = true
		}
		for _, i := range offsetsWorthDriving(c.in, append(own, all...)) {
			if !kept[i] {
				crossPattern = append(crossPattern, c.id())
				break
			}
		}
	}

	if len(crossPattern) == 0 {
		t.Error("no corpus case holds a value a built-in outside its own set locates at an offset its own set does not reach, " +
			"so caseBounds asking the whole registry buys nothing; write a case that does, or say in caseBounds that the corpus no longer holds one")
	}
	if len(noValue) == 0 {
		t.Error("no corpus case masked with its own set locates nothing, so offsetsDriven's fall back to every offset is reached by no case; " +
			"write a case that locates nothing, or say in offsetsDriven that the corpus no longer holds one")
	}
	t.Logf("%d case(s) reach an offset only the whole registry finds, %d case(s) locate nothing at all, out of %d",
		len(crossPattern), len(noValue), len(cases))
}

func TestProperties_everyPrefix(t *testing.T) {
	// A log line cut to a column limit, a read that stopped early, a value
	// still being written: text arrives cut short, and every case is masked
	// here cut at the offsets offsetsDriven walks. A scan reading past the end
	// of its input, or resuming past what it has not consumed, shows up as a
	// redaction that no longer restores to the text it came from.
	cases := readableCases(t)
	bounds := caseBounds(t, cases)
	for _, set := range builtinSets {
		t.Run(set.name, func(t *testing.T) {
			t.Parallel()
			ms := newMasking(set.patterns)
			for j, c := range cases {
				for _, i := range offsetsDriven(c.in, bounds[j]) {
					ms.check(t, c.in[:i])
				}
			}
		})
	}
}

func TestProperties_everySuffix(t *testing.T) {
	// The other end: text that begins in the middle of a value, as a reader
	// resuming from an offset leaves it.
	cases := readableCases(t)
	bounds := caseBounds(t, cases)
	for _, set := range builtinSets {
		t.Run(set.name, func(t *testing.T) {
			t.Parallel()
			ms := newMasking(set.patterns)
			for j, c := range cases {
				for _, i := range offsetsDriven(c.in, bounds[j]) {
					ms.check(t, c.in[i:])
				}
			}
		})
	}
}

// injected is the bytes pushed into a case: the ones the built-in scans key on,
// the ones that end a run, and bytes text cannot hold.
//
// Each byte here stands for a class a scan's own declarations read
// differently, and is kept only where no other byte here already reads that
// class:
//
//   - '/' and '+' are two characters of the standard base64 alphabet — not
//     base64url's, which '-' and '_' already stand for — that
//     AWSSecretAccessKey, FlyIoAccessToken, PrivateKey and SentryAuthToken
//     all read as part of a value's body rather than as its end.
//   - '=' is base64's padding character, which those same bodies read as
//     ending a run rather than extending one, and which AWSSecretAccessKey's
//     isAWSSecretAccessKeyAssignment also reads as an assignment character
//     between a name and a value.
//   - '"' is what AWSSecretAccessKey's isAWSSecretAccessKeyQuote reads around
//     a value, the plain apostrophe it also admits being no different a
//     class.
//   - '\t' is what AWSSecretAccessKeySpace reads as a space, alongside ' '.
//   - '\r' is half of the "\r\n" line break PrivateKey reads as one of its
//     four spellings, a class '\n' alone does not stand for.
//   - 'A' and 'Z' are what an uppercase letter does to a lowercase
//     hexadecimal or base62 body: 'A' is a valid hexadecimal digit in that
//     case and 'Z' is not, so the two read different boundaries of the same
//     alphabets.
//
// ':' is left out: AWSSecretAccessKey's isAWSSecretAccessKeyAssignment reads
// it exactly where it reads '=', so '=' already drives that branch, and a
// separator no scan recognises at all is already what '.' drives. The corpus
// still states ':' as a separator directly —
// builtin_aws_secret_access_key.txt's "under the name a workflow input
// writes" and "the words written out" cases both use it.
//
// 0x80, 0xc3, 0xe6 and 0xf0 are left out too: every alphabet a built-in scan
// tests membership in (isBase64URLByte, isBase62Byte and the rest) is a plain
// ASCII range comparison, so a continuation byte, a lead byte of any width and
// 0xff all fail every one of them the same way — none of a scan's own
// declarations reads them apart. 0xff, already below, is the one
// representative that class needs. Where the byte's width genuinely matters —
// a rune truncated after one, two or three of its continuation bytes —
// degenerate.txt states it directly, with the exact text the truncation
// leaves, rather than through every position of every other case here.
var injected = []byte{
	'.', '_', '-', '/', '+', '=', '"',
	'g', 'e', 'y', 'A', 'Z', '0', ' ', '\t', '\r', '\n',
	0x00, 0xff,
}

// denseText is the length up to which a byte is pushed into every position of a
// text rather than into the positions offsetsWorthDriving picks out. It
// separates a text short enough that driving every position of it costs little
// from one where it does not.
//
// Most of the corpus is longer than it, so what it decides is the density of a
// minority of cases; the offsets a long case is driven at are the rule below.
const denseText = 48

// offsetStride is how far apart the offsets offsetsWorthDriving keeps are where
// nothing about a value singles one out.
//
// It is a sampling interval and no argument rests on it: what the rule below
// exists to keep is the edges of every value and both ends of the text, and
// those are kept whatever the stride is. Widening it trades time for the
// chance that a scan goes wrong at an offset no value stands near.
const offsetStride = 8

// everyOffset returns every offset of src, which is every position a byte can
// be pushed into and every place the text can be cut in two.
func everyOffset(src string) []int {
	offsets := make([]int, 0, len(src)+1)
	for i := range len(src) + 1 {
		offsets = append(offsets, i)
	}
	return offsets
}

// offsetsWorthDriving returns the offsets of src worth driving where every one
// of them is too many: the edges of every redaction it holds, where a scan that
// has just decided something is about to be caught deciding it differently,
// with every offsetStride'th offset and both ends behind them.
//
// bounds may be nil, and what is left then is the stride and the ends.
func offsetsWorthDriving(src string, bounds [][2]int) []int {
	seen := map[int]bool{}
	var offsets []int
	add := func(i int) {
		if i < 0 || i > len(src) || seen[i] {
			return
		}
		seen[i] = true
		offsets = append(offsets, i)
	}
	for _, b := range bounds {
		start, end := b[0], b[1]
		add(start - 1)
		add(start)
		add(start + 1)
		add(end - 1)
		add(end)
		add(end + 1)
	}
	for i := 0; i <= len(src); i += offsetStride {
		add(i)
	}
	add(len(src))
	return offsets
}

// offsetsDriven returns the offsets of src the properties walk, which is every
// one of them without the race detector and the ones above with it.
//
// These properties drive one input per offset of every case through every
// built-in set, and builtinSets is derived from AllBuiltinPatterns: a pattern
// added grows the sets by one and the corpus by a file, so the product of the
// two grows with every pattern and the detector multiplies the whole of it.
// That is why the growth is not something a faster machine settles.
//
// CI gives the run under the detector ten minutes, and a run of it varies by
// more than a tenth between two runs of the same commit — one such pair timed
// out and passed. So what the budget has to hold is a spread rather than a
// number, and a suite that fits only on its good runs does not fit. That is
// what this is aimed well under the limit for rather than just inside it.
//
// What moves under the detector is the scale and not the test, which is what
// CLAUDE.md asks for. Every set and every case is still driven, and so are both
// ends of every case and the edges of every value in it, under its own patterns
// and under the whole registry alike — the offsets where a scan decides
// something. What is dropped is the middle of a run, where the answer at one
// offset is the answer at the one before it.
//
// A case holding no value at all is driven at every offset even here, and that
// is the point rather than an exception. Those are the cases written to be near
// misses — a body one character short, an alphabet broken one byte in — so an
// offset in one is a place a scan decides something rather than the middle of a
// run, and there are no edges to sample around, since nothing is located to
// have edges. They are a large part of every offset walked here, which makes
// holding them to the stride the obvious way to make this faster and the wrong
// one. TestProperties_offsetsDrivenReachesWhatItIsFor counts them, so that the
// number is not a sentence here to go stale.
//
// Nothing is skipped and no input leaves CI: the job without the detector runs
// go test ./... over the whole corpus at every offset, so the dense half of
// this is what that job is for.
func offsetsDriven(src string, bounds [][2]int) []int {
	if raceEnabled && len(bounds) > 0 {
		return offsetsWorthDriving(src, bounds)
	}
	return everyOffset(src)
}

// injectionPoints returns where a byte is pushed into src: every position of a
// short text, and of a longer one the offsets offsetsWorthDriving keeps.
//
// Under the race detector the length is not read at all, so a short text is no
// denser than a long one there. offsetsDriven says why the detector is where
// that half is dropped.
//
// This is the one place that keeps the sparse offsets where a text holds no
// value at all, rather than falling back to every offset the way offsetsDriven
// does. What is driven here is not a truncation but the whole text with a byte
// pushed into it, so an offset in a clean case is not a place a scan decides
// something the way the end of a prefix is; and whatever offsets are kept here
// are driven once for every byte in injected.
func injectionPoints(src string, bounds [][2]int) []int {
	if raceEnabled || len(src) > denseText {
		return offsetsWorthDriving(src, bounds)
	}
	return everyOffset(src)
}

func TestProperties_aByteInTheMiddle(t *testing.T) {
	// A byte pushed into a value breaks it, and a byte pushed beside one must
	// not. Either way what comes out has to put back together into what went
	// in, which is what a scan whose cursor runs past a byte it did not consume
	// stops doing.
	//
	// Where a byte is pushed into a case is read out of what that case masks
	// to, which is the same answer for every set it is then driven through. It
	// is worked out once here rather than inside the set loop below, where the
	// corpus would be masked again for every set there is.
	cases := readableCases(t)
	bounds := caseBounds(t, cases)
	points := make([][]int, len(cases))
	for i, c := range cases {
		points[i] = injectionPoints(c.in, bounds[i])
	}

	for _, set := range builtinSets {
		t.Run(set.name, func(t *testing.T) {
			t.Parallel()
			ms := newMasking(set.patterns)
			for i, c := range cases {
				t.Run(c.subtest(), func(t *testing.T) {
					for _, b := range injected {
						for _, at := range points[i] {
							ms.check(t, c.in[:at]+string(b)+c.in[at:])
						}
					}
				})
			}
		})
	}
}

func TestProperties_casesRunTogether(t *testing.T) {
	// Text does not arrive one case at a time. Cases are run together, with and
	// without a newline between them, so that a value ending where another
	// begins is masked as what it is rather than as what the pair looks like.
	cases := readableCases(t)
	for _, set := range builtinSets {
		t.Run(set.name, func(t *testing.T) {
			t.Parallel()
			ms := newMasking(set.patterns)
			for i, c := range cases {
				for k := 1; k <= 6; k++ {
					other := cases[(i+k)%len(cases)]
					for _, sep := range []string{"", "\n", " ", "."} {
						ms.check(t, c.in+sep+other.in)
					}
				}
			}
		})
	}
}

func TestProperties_repeatedCases(t *testing.T) {
	// A value repeated is a value every time. A scan that carries a cursor
	// forward through a run, as several of the built-in scans do, is what this
	// is aimed at: the second value must not be lost to what the first left
	// behind.
	cases := readableCases(t)
	for _, set := range builtinSets {
		t.Run(set.name, func(t *testing.T) {
			t.Parallel()
			ms := newMasking(set.patterns)
			for _, c := range cases {
				t.Run(c.subtest(), func(t *testing.T) {
					for _, sep := range []string{"", "\n", " "} {
						ms.check(t, strings.Repeat(c.in+sep, 8))
					}
				})
			}
		})
	}
}

func TestProperties_maskerIsReusable(t *testing.T) {
	// A Masker is built once and handed everything a program logs. Driving
	// every readable case through a single Masker holds what a built-in scan
	// keeps between calls — a cursor, a decoder — to keeping nothing that
	// outlives the call it belongs to.
	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))
	cases := readableCases(t)

	want := make([]string, len(cases))
	for i, c := range cases {
		want[i] = mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...)).Mask(c.in)
	}
	for round := range 3 {
		for i, c := range cases {
			if got := m.Mask(c.in); got != want[i] {
				t.Fatalf("round %d: %s: Mask(%q) = %q, want %q", round, c.id(), c.in, got, want[i])
			}
		}
	}
}

func TestProperties_redactorSeesTheValue(t *testing.T) {
	// What a redactor is handed is the text about to be redacted, and the
	// pattern that located it. A redactor writing the value straight back must
	// therefore leave the text untouched, whatever was located in it.
	identity := mask.NewRedactor(func(m mask.Match) string { return m.Value })

	for _, c := range corpusCases(t) {
		m := maskerWith(c.patterns(), identity)
		if got := m.Mask(c.in); got != c.in {
			t.Errorf("%s: a redactor writing the value back changed %q into %q", c.id(), c.in, got)
		}
	}
}

func TestProperties_redactorSeesThePattern(t *testing.T) {
	// The pattern a Match carries is the one the caller gave, the same value
	// every time, so that a redactor can key on it by identity rather than by
	// name.
	for _, c := range corpusCases(t) {
		patterns := c.patterns()
		known := make(map[mask.Pattern]bool, len(patterns))
		for _, p := range patterns {
			known[p] = true
		}

		var seen int
		m := maskerWith(patterns, mask.NewRedactor(func(match mask.Match) string {
			seen++
			if !known[match.Pattern] {
				t.Errorf("%s: a value was attributed to a pattern the masker was not given", c.id())
			}
			return ""
		}))
		m.Mask(c.in)
		if want := len(c.names(t)); seen != want {
			t.Errorf("%s: the redactor was called %d time(s), the case holds %d value(s)", c.id(), seen, want)
		}
	}
}

func TestProperties_noValueLeaksThroughAnyRedactor(t *testing.T) {
	// Whatever a redactor writes, what it was given must not be in the output
	// unless the redactor itself put it there. The redactors below are the ones
	// a caller reaches for.
	redactors := []struct {
		name     string
		redactor mask.Redactor
	}{
		{name: "Fill('*')", redactor: mask.Fill('*')},
		{name: `Fixed("[REDACTED]")`, redactor: mask.Fixed("[REDACTED]")},
		{name: `Fixed("")`, redactor: mask.Fixed("")},
		{name: "marking", redactor: markRedactor},
	}

	for _, c := range readableCases(t) {
		_, values := maskMarked(c.patterns(), c.in)
		for _, r := range redactors {
			got := maskerWith(c.patterns(), r.redactor).Mask(c.in)
			for _, value := range values {
				if strings.Count(c.in, value) == 1 && strings.Contains(got, value) {
					t.Errorf("%s: with %s, %q still holds %q", c.id(), r.name, got, value)
				}
			}
		}
	}
}

func TestProperties_morePatternsRedactNoLess(t *testing.T) {
	// AllBuiltinPatterns: "The set grows as patterns are added to this
	// package." A corpus case masked with a set holding one built-in alone is
	// how TestCorpus_coversEveryBuiltinPattern states what that pattern
	// locates on its own, but a caller reaching for one built-in reaches for
	// AllBuiltinPatterns instead, which is the whole registry scanning the
	// same text at once. This is what states the difference cannot cost a
	// value: whatever one pattern alone locates, the whole registry must
	// still redact.
	//
	// It could fail two ways checkPrefilter and Test_builtins_retainSettles
	// (root package) do not reach: a pattern's own openings turning it away
	// on text another pattern's grammar would have opened a candidate in —
	// which is what customSets' scans are for, but not what the corpus's own
	// ~2600 builtin_<name>.txt inputs are ever driven through — or two
	// built-ins disagreeing about where a value ends and the shorter of the
	// two winning attribution while stopping short of what the longer would
	// have redacted.
	all := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...), mask.WithRedactor(mask.Fill('*')))
	builtin := map[mask.Pattern]bool{}
	for _, p := range mask.AllBuiltinPatterns() {
		builtin[p] = true
	}

	driven := 0
	for _, c := range corpusCases(t) {
		patterns := c.patterns()
		if len(patterns) != 1 || !builtin[patterns[0]] {
			continue // not a case masked with one built-in alone
		}
		_, values := maskMarked(patterns, c.in)
		if len(values) == 0 {
			continue // a clean case; nothing here to lose
		}
		driven++
		got := all.Mask(c.in)
		for _, v := range values {
			if strings.Count(c.in, v) == 1 && strings.Contains(got, v) {
				t.Errorf("%s: %s alone redacts %q out of %q, but the whole registry's Mask gives %q, which still holds it",
					c.id(), patterns[0].Name(), v, c.in, got)
			}
		}
	}
	if driven == 0 {
		t.Fatal("no case masked with one built-in alone located anything, so this drove nothing")
	}
}

// builtinValues is one located value per built-in pattern, taken from the
// corpus's own per-pattern cases: the first case masked with that pattern
// alone that locates exactly one value, and one that pattern goes on to
// locate standing entirely on its own.
//
// A value taken from the corpus rather than built here is a value already
// held to being one that pattern locates on its own — TestCorpus_summary
// counts every pattern with at least one such case, and TestCorpus_summary's
// sibling TestCorpus_coversEveryBuiltinPattern asks for at least three.
//
// The last check leaves out a pattern such as AWSSecretAccessKey, whose
// Match.Value is the forty characters alone: its own doc states they are
// located "standing behind the name it is assigned to", so the name is what a
// case's in field carries and Match.Value never does. Pairing such a value
// with another builtin's, with nothing standing in for the name, is not a
// question this test's concatenation can put to that pattern at all — the
// gap is in what the corpus states about the pattern needing a name nearby,
// not in this property.
func builtinValues(t testing.TB) map[string]string {
	t.Helper()

	builtin := map[mask.Pattern]bool{}
	for _, p := range mask.AllBuiltinPatterns() {
		builtin[p] = true
	}

	values := make(map[string]string, len(mask.AllBuiltinPatterns()))
	for _, c := range corpusCases(t) {
		patterns := c.patterns()
		if len(patterns) != 1 || !builtin[patterns[0]] {
			continue // not a set holding one built-in alone
		}
		name := patterns[0].Name()
		if _, ok := values[name]; ok {
			continue
		}
		_, vs := maskMarked(patterns, c.in)
		if len(vs) != 1 || vs[0] != c.in {
			continue // not a case whose whole in is the one value located
		}
		values[name] = vs[0]
	}
	return values
}

func TestProperties_everyPairOfBuiltins(t *testing.T) {
	// TestProperties_casesRunTogether pairs a case with six neighbours chosen
	// by where the corpus's files happen to sort, so which of the ~4400
	// ordered pairs of built-ins is exercised drifts as cases are added or
	// files renamed, and most pairs are never driven beside each other at
	// all. This drives every ordered pair instead, directly: one value per
	// built-in, written beside another with nothing, a newline, a space or a
	// dot between them, under the whole registry.
	values := builtinValues(t)
	names := slices.Sorted(maps.Keys(values))

	// nonContributingBuiltins is how many of AllBuiltinPatterns() contribute
	// no value to builtinValues. Held to exactly, the way TestCorpus_summary
	// holds knownCollisions to a count rather than a bound: builtinValues's
	// own doc names the one pattern this covers — AWSSecretAccessKey, whose
	// Match.Value is the forty characters alone and never a value standing on
	// its own, so no single-value corpus case can seed it here. A pattern
	// that quietly stops contributing — a corpus edit that puts a keyword
	// prefix on what was its only single-value case, say — moves this count
	// without moving nonContributingBuiltins, and only counting catches that;
	// the fewer names drive fewer of the ~4400 ordered pairs this test
	// exists to state something about.
	const nonContributingBuiltins = 1
	if want := len(mask.AllBuiltinPatterns()) - nonContributingBuiltins; len(names) != want {
		contributed := make(map[string]bool, len(names))
		for _, n := range names {
			contributed[n] = true
		}
		var missing []string
		for _, p := range mask.AllBuiltinPatterns() {
			if !contributed[p.Name()] {
				missing = append(missing, p.Name())
			}
		}
		t.Fatalf("%d built-in(s) contributed a value, want %d (nonContributingBuiltins=%d) — missing: %v",
			len(names), want, nonContributingBuiltins, missing)
	}

	// robustLeadingAlnum and robustTrailingAlnum say whether a pattern still
	// gets its own value fully redacted with a letter or a digit standing
	// directly against it — in front for the first, behind for the second.
	// Several of the built-ins document the opposite by name for the leading
	// side — SlackToken and StripeSecretKey both require "no letter or digit
	// stands in front of it" — and every one of this library's own values
	// both ends and, read as vq, begins in one, so concatenating two of them
	// with nothing between is asking a question those patterns' own docs
	// already answer rather than testing an adjacency defect. A pattern
	// requiring the mirror image on its trailing side is answered the same
	// way. Both are computed once per name against a plain digit rather than
	// assumed from a name, so a pattern with either requirement arriving
	// later is read correctly without this test naming it.
	//
	// The two probes ask different questions of the match, on purpose. A scan
	// walking forward from a prefix has no way to extend a match earlier than
	// where it opened, so prepending "9" either leaves q's value exactly as
	// reported (this is a false positive) or blocks it outright the way
	// Slack's and Stripe's own leading rule does — an exact-match check tells
	// those two apart. Appending "9" is not symmetric: several bodies here
	// are variable-length and read as far as their alphabet allows, so the
	// same digit is often just one more character of the body, extending the
	// reported match rather than being refused. The question that matters
	// downstream is only whether vp survives being redacted, not whether the
	// match that redacts it stops exactly at vp's own end — so this asks
	// whether some match's Value carries vp as a prefix, true whether that
	// match is vp exactly or vp with the digit read onto it, and false only
	// where a trailing boundary rule, the mirror of Slack's and Stripe's own,
	// would leave vp itself standing in the output.
	robustLeadingAlnum := make(map[string]bool, len(names))
	robustTrailingAlnum := make(map[string]bool, len(names))
	for _, q := range names {
		_, vs := maskMarked(mask.AllBuiltinPatterns(), "9"+values[q])
		robustLeadingAlnum[q] = len(vs) == 1 && vs[0] == values[q]

		_, vs = maskMarked(mask.AllBuiltinPatterns(), values[q]+"9")
		robustTrailingAlnum[q] = slices.ContainsFunc(vs, func(v string) bool { return strings.HasPrefix(v, values[q]) })
	}

	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...), mask.WithRedactor(mask.Fill('*')))
	for _, p := range names {
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			vp := values[p]
			for _, q := range names {
				vq := values[q]
				for _, sep := range []string{"", "\n", " ", "."} {
					// sep == "" concatenates vp directly against vq: vp's
					// trailing edge meets vq's leading edge with nothing
					// between them, so both sides of that seam need to be
					// robust to an alnum neighbour for the pair to say
					// anything about an adjacency defect rather than about a
					// prefix's own documented requirement.
					if sep == "" && (!robustTrailingAlnum[p] || !robustLeadingAlnum[q]) {
						continue
					}
					src := vp + sep + vq
					got := m.Mask(src)
					if strings.Contains(got, vp) && strings.Count(src, vp) == 1 {
						t.Errorf("%s beside %s over %q: Mask gives %q, which still holds %s's own value", p, q, src, got, p)
					}
					if strings.Contains(got, vq) && strings.Count(src, vq) == 1 {
						t.Errorf("%s beside %s over %q: Mask gives %q, which still holds %s's own value", p, q, src, got, q)
					}
					if sep == " " {
						// checkCase's affix property already states that a
						// value standing alone after "log: " is located; a
						// second credential in front of it, separated only by
						// a space, must not cost either one.
						log := "log: " + src
						got := m.Mask(log)
						if strings.Contains(got, vp) && strings.Count(log, vp) == 1 {
							t.Errorf("%s beside %s, logged: Mask(%q) = %q, which still holds %s's own value", p, q, log, got, p)
						}
						if strings.Contains(got, vq) && strings.Count(log, vq) == 1 {
							t.Errorf("%s beside %s, logged: Mask(%q) = %q, which still holds %s's own value", p, q, log, got, q)
						}
					}
				}
			}
		})
	}
}

func TestProperties_manyValues(t *testing.T) {
	// TestConformance's "twice over" property and TestProperties_repeatedCases
	// hold a value repeated eight times; a leaked key material dump or a
	// repeated log line repeats one thousands of times over, with no scan
	// state carried between calls to answer for. This drives a single value
	// at that scale, through Mask directly and through a Writer a byte at a
	// time, both held to the same rune-count and no-value-survives properties
	// checkCase already states at a smaller scale.
	const n = 5000
	const value = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	m := mask.New(mask.WithPatterns(mask.GitHubToken()), mask.WithRedactor(mask.Fill('*')))

	adjacent := strings.Repeat(value, n)
	if got, want := m.Mask(adjacent), strings.Repeat("*", n*utf8.RuneCountInString(value)); got != want {
		t.Errorf("masking %d adjacent values gave %d asterisk(s), want %d", n, strings.Count(got, "*"), strings.Count(want, "*"))
	}

	separated := strings.Repeat(value+"\n", n)
	wantLine := strings.Repeat("*", utf8.RuneCountInString(value)) + "\n"
	if got, want := m.Mask(separated), strings.Repeat(wantLine, n); got != want {
		t.Errorf("masking %d values separated by newlines did not give %d repeats of one masked line", n, n)
	}

	pieces := make([]string, len(separated))
	for i := range len(separated) {
		pieces[i] = separated[i : i+1]
	}
	checkStream(t, m, separated, m.Mask(separated), pieces)
}

func TestProperties_customPatternSets(t *testing.T) {
	// builtinSets is what every property above drives — the built-in
	// patterns and each of them alone — leaving the sets a caller's own
	// patterns are stated with (regexp, a mask group, a function) undriven by
	// text derived from their cases: no prefix or suffix of one, no byte
	// pushed into its match, no repetition of it. Restricted to the cases
	// each such set is its own — a case masked with the built-ins already
	// runs through every property above — this drives the same shapes over
	// them.
	sets := map[string][]mask.Pattern{}
	var cases []*corpusCase
	for _, c := range readableCases(t) {
		if _, ok := customPatternSets[c.set]; !ok {
			continue // a built-in set on its own; driven above already
		}
		if c.set == "default" || c.set == "default-and-regexp" || c.set == "none" {
			continue // the built-ins at scale, driven above; none locates nothing to derive text from
		}
		sets[c.set] = c.patterns()
		cases = append(cases, c)
	}
	if len(sets) == 0 {
		t.Fatal("no custom pattern set has a readable case")
	}

	for setName, patterns := range sets {
		t.Run(setName, func(t *testing.T) {
			t.Parallel()
			ms := newMasking(patterns)
			for _, c := range cases {
				if c.set != setName {
					continue
				}
				t.Run(c.name, func(t *testing.T) {
					for i := range len(c.in) + 1 {
						ms.check(t, c.in[:i])
						ms.check(t, c.in[i:])
					}
					for _, sep := range []string{"", "\n", " "} {
						ms.check(t, strings.Repeat(c.in+sep, 8))
					}
				})
			}
		})
	}
}

func TestProperties_everyCaseThroughEveryBuiltinSet(t *testing.T) {
	// Every case, whatever it was written for, through every built-in set. A
	// case written for one pattern says nothing about another, but nothing may
	// go wrong when it reaches one.
	cases := corpusCases(t)
	for _, set := range builtinSets {
		t.Run(set.name, func(t *testing.T) {
			t.Parallel()
			ms := newMasking(set.patterns)
			for _, c := range cases {
				t.Run(c.subtest(), func(t *testing.T) {
					ms.check(t, c.in)
				})
			}
		})
	}
}
