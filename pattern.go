package mask

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Span is a half-open byte range [Start, End) within the scanned text. Offsets
// are zero-based, and Start must be less than End.
type Span struct {
	Start int
	End   int
}

// LookBehind is how far in front of a value a Pattern may read: the bytes from
// LookBehind before the start of a span it reports up to that start, and no
// further back.
//
// A Masker scanning a whole string hands every pattern the whole of it and the
// limit costs nothing. It is what NewReader and NewWriter rest on: a stream is
// masked by scanning a window that moves along it, and text the window has
// already carried past is what those readers keep rather than release. The
// limit is what tells them how much to keep.
//
// Stated as a demand on a Find: hand it the text from an offset k on rather
// than the whole, where Find has settled at least k + LookBehind of the whole,
// and from k + LookBehind on it must report what it reports when handed
// everything. What that rules out is a Find whose answer at one place depends
// on the whole of the text in front of it. A scan walking the text from the
// start and stepping over each value it found would be such a Find: where the
// window begins would decide where the values fall, and a value would move
// under the window as the window moved.
//
// Every built-in pattern reads at most one byte in front of a value — the
// character a prefix may not stand behind — and a pattern built by MustRegexp
// reads one rune, which is what \b, \B and ^ are decided by. The limit is far
// above both so that a Pattern written by hand has room to read a keyword or an
// assignment in front of what it locates. A Find that cannot be held to it,
// where a value is decided by more text in front of it than this, must settle
// nothing: what settles nothing is never handed a window.
const LookBehind = 64

// Pattern locates sensitive values in text.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type Pattern interface {
	// Name identifies the pattern. It should be stable, lowercase and
	// hyphenated, such as "github-token".
	Name() string

	// Find returns the byte ranges to redact in src, and the offset from
	// which src is not yet settled.
	//
	// The spans may be unordered and may overlap; a Masker sorts them and
	// resolves the overlaps. Spans reaching outside src, and spans whose
	// Start is not less than their End, are ignored.
	//
	// Both ends must fall on a rune boundary. A span cutting a multi-byte
	// rune in half is neither ignored nor repaired: the bytes either side of
	// it are written back as they were found, so what is left of that rune
	// stands beside the redaction and the output is not valid UTF-8. The
	// built-in patterns and MustRegexp cannot report such a span — every
	// built-in decides its ends on an ASCII alphabet, and Go's regexp
	// matches runes — so this is a demand on a Find written by hand.
	//
	// retain answers what src alone cannot: whether src is all there is. For
	// every text beginning with src, the values in it that begin before
	// retain are exactly the spans reported here that begin before retain,
	// with the same Start and the same End. Nothing is promised about what
	// begins at retain or after it: a value there may grow, may appear where
	// nothing was reported, and may turn out to be no value at all.
	//
	// Both directions of that are load-bearing. A value the shorter text
	// misses is one a stream writes out before it is found; one it reports
	// that the longer text does not is a redaction a stream cannot take
	// back.
	//
	// Zero promises nothing and is always true. It is what a Find written
	// without a stream in mind returns, and what a Find returns when the
	// whole of src is still open — a value running to the end of it that
	// more text would carry further. Reporting len(src) says the opposite:
	// src stands complete, and nothing appended to it changes any of this.
	//
	// Mask reads the whole of its input at once and ignores retain. NewReader
	// and NewWriter are what it is for: they hold back the text from retain
	// on until more of the stream settles it.
	Find(src string) (spans []Span, retain int)
}

// NewPattern returns a Pattern that reports name as its name and locates
// values with find:
//
//	mask.NewPattern("high-entropy", func(src string) ([]mask.Span, int) {
//		// ...
//		return spans, len(src)
//	})
//
// find must be safe for concurrent use by multiple goroutines, and owes what
// Pattern.Find says about both of its results.
func NewPattern(name string, find func(src string) (spans []Span, retain int)) Pattern {
	return &funcPattern{name: name, find: find}
}

type funcPattern struct {
	name string
	find func(src string) (spans []Span, retain int)
}

func (p *funcPattern) Name() string { return p.name }

func (p *funcPattern) Find(src string) ([]Span, int) { return p.find(src) }

// MustRegexp returns a Pattern backed by expr, and panics if expr is invalid.
//
// The whole match is redacted, unless expr contains a capture group named
// "mask", in which case only that group is:
//
//	// "Authorization: Bearer abc123" -> "Authorization: Bearer ******"
//	mask.MustRegexp("bearer-token", `Bearer (?P<mask>[\w.~+/-]+=*)`)
//
// Go admits the name more than once, which is what a marker written in
// variants asks for — one branch of an alternation apiece — and every group
// named "mask" that took part in the match is redacted. A match where none of
// them did is redacted nowhere.
//
// Where the expression has a ceiling on its width, every match it admits is
// located, including the ones that begin inside another: forty characters of
// hexadecimal written against forty more are redacted whole, where Go's FindAll
// resumes past each match it takes and would leave the second forty. What that
// costs is a second run of the expression at each position inside a match where
// one could open — nothing where matches are rare, and what a caller pays for
// an expression matching densely and never far.
//
// What such a pattern settles, in the sense Pattern.Find gives the word, is
// worked out from expr two ways. A match can be no wider than the expression
// can match, so everything more than that many bytes in front of the end of the
// text is settled; and a match opens with whatever literal the expression opens
// with, so the text in front of the first place that literal could stand holds
// no match and is settled whatever the width.
//
// An expression that can match text of any width — one written with * or + or
// an open repetition — has only the second of those, and one naming no literal
// to open with has neither and settles nothing at all. A Reader or a Writer
// holds what no pattern has settled, and gives up holding at WithMaxRetained by
// redacting what it holds, so such an expression turns everything from a
// match's opening onwards into a redaction once the limit is reached — whether
// or not a match was ever written there. Write a counted repetition for a
// pattern a stream is to mask with: INT-[0-9a-f]{32} rather than
// INT-[0-9a-f]+.
func MustRegexp(name, expr string) Pattern {
	re := regexp.MustCompile(expr)
	var mask []int
	for i, sub := range re.SubexpNames() {
		if sub == "mask" {
			mask = append(mask, i)
		}
	}

	// after matches expr one rune along from where it is handed, which is how
	// a candidate standing inside another match is tried without losing the
	// character in front of it. \b, \B and ^ are decided by that character, and
	// a candidate tried on the text from itself onwards would have them decided
	// as though it stood at the beginning of the text. The rune is skipped
	// inside a group of its own so that a flag expr opens with reaches expr
	// alone, and \A inside expr is then unsatisfiable, which is what it should
	// be anywhere but the beginning.
	//
	// Wrapping is what an expression already at the size a regexp may compile
	// to can fail on, and nothing else: the syntax around expr is closed, so an
	// expression MustCompile accepted stays syntactically whole inside it. Such
	// a pattern locates what the walk alone finds, and settles nothing, since
	// what it locates then depends on the text in front of it and a stream must
	// not let go of any of that.
	after, wrapped := regexp.Compile(`\A(?s:.)(?:` + expr + `)`)
	if wrapped != nil {
		after = nil
	}

	// regexp.Compile parses with syntax.Perl, so the tree walked here is the
	// tree the matcher was built from. The error is dropped rather than
	// reported because MustCompile above has already accepted expr: reaching
	// this line at all means the parse succeeds.
	parsed, err := syntax.Parse(expr, syntax.Perl)
	width := regexpUnbounded
	if err == nil && after != nil {
		width = regexpMaxWidth(parsed)
	}
	// What every match opens with, which bounds where one can begin. Go reports
	// it whether or not it is the whole expression, and the empty string where
	// there is none.
	literal, _ := re.LiteralPrefix()

	// Whether a window over part of a text may be opened on this pattern at
	// all, which is what settling anything amounts to. Three things have to
	// hold, and each of them is a way the answer would otherwise turn on where
	// the window begins rather than on the text:
	//
	//   - a candidate inside a match can be tried, which is what the wrapped
	//     expression is for and what a failure to wrap it takes away;
	//   - something bounds where a match can begin — a ceiling on its width, or
	//     a literal it must open with — since with neither, nothing is settled
	//     anywhere and a window never opens;
	//   - a group named "mask" stands near enough to the beginning of a match
	//     that a Masker drops it along with the match. A window opens
	//     LookBehind bytes in front of the text still to be written out, and a
	//     match beginning in the first rune of that opening is one this pattern
	//     may be wrong about — there is no whole rune in front of it for \b or
	//     ^ to be decided by. A Masker drops what begins in the opening, so
	//     such a match is dropped; the group it redacts is dropped with it
	//     only where the group stands inside the opening too, which is what
	//     leaves a rune's worth of room below the limit here.
	masks := regexpUnbounded
	if err == nil {
		masks = regexpMaskDistance(parsed)
	}
	streams := after != nil &&
		(width != regexpUnbounded || literal != "") &&
		(masks == regexpNoMaskGroup ||
			(masks != regexpUnbounded && masks+utf8.UTFMax <= LookBehind))

	return &regexpPattern{
		name:        name,
		re:          re,
		after:       after,
		mask:        mask,
		width:       width,
		literal:     literal,
		literalTail: newPrefixTail(literal),
		streams:     streams,
		coalesces:   err == nil && !regexpReadsBehind(parsed),
		probes:      streams && width != regexpUnbounded,
	}
}

type regexpPattern struct {
	name string
	re   *regexp.Regexp
	// after is expr with one rune in front of it, anchored, which is what a
	// candidate inside another match is tried with. It is nil only where
	// wrapping expr failed, which leaves the matches FindAll reports and
	// nothing else.
	after *regexp.Regexp
	// mask holds the submatch index of every group named "mask", and is
	// empty when expr names none. All of them rather than one, because
	// SubexpIndex reports the leftmost of the groups sharing a name: taking
	// that one alone would read the group of a branch that did not match, see
	// it take part in nothing and drop the whole match — an alternation
	// naming the group in each of its branches would then redact the first
	// branch and pass the rest through untouched.
	mask []int
	// width is the widest match expr admits, in bytes, or regexpUnbounded
	// where it admits one of any width.
	width int
	// literal is what every match opens with, and is empty where expr names no
	// such thing. literalTail is the same read at the end of a text.
	literal     string
	literalTail prefixTail
	// streams says whether a window over part of a text may be opened on this
	// pattern. Where it may not, nothing is ever settled and no window opens.
	streams bool
	// coalesces says whether a span overlapping the one before it is widened
	// into it rather than reported beside it. add says what decides it.
	coalesces bool
	// probes says whether a candidate inside a match is tried, which is what
	// makes the matches reported here the matches themselves rather than the
	// walk Go's FindAll happens to take — and so what makes this pattern answer
	// the same about a place in the text however much of the text in front of
	// that place it is shown.
	//
	// Only an expression with a ceiling on its width needs it. What a window
	// may cut is what the pattern settled, less LookBehind; an expression with
	// no ceiling settles by the literal a match opens with and nothing else, so
	// what it settles stands in front of every match there is and a window over
	// it never opens inside one. Trying every position inside a match of no
	// fixed width would also read to the end of the text from each of them,
	// which is time quadratic in a run the expression matches the whole of.
	probes bool
}

func (p *regexpPattern) Name() string { return p.name }

func (p *regexpPattern) Find(src string) ([]Span, int) {
	spans := p.find(src)

	// A span reaching the end of the input is one more text can carry further,
	// so nothing from where it begins is settled. Neither is a span reaching
	// past what the arithmetic settled: a match beginning inside one already
	// reported widens that one rather than standing beside it, so a match
	// beginning in text that is not settled yet moves the span that already
	// covers it. Either way the span that moves is the earlier of the two, and
	// what is settled is at most where it begins.
	//
	// Walked from the end over the spans in the order they begin, which is what
	// makes one pass the whole of the rule rather than one application of it.
	// Pulling the offset back brings the spans in front of it into the same
	// question and none of the spans behind it, so a walk that has already
	// passed everything beginning later is a walk with nothing left to revisit:
	// a chain of spans each reaching past where the next begins drains here in
	// one pass, where a forward walk drains a link of it a pass and a repeated
	// pass over an unordered list drains an inversion a pass. Either of those
	// is a pass a span, which is a pass a byte on the texts below.
	//
	// find does not report them in that order. A probe run inside a match can
	// yield a mask group opening in front of one the enclosing match already
	// reported, so (?P<mask>[a-z]{1,3})[0-9]{1,3}(?P<mask>[a-z]{1,3}) over
	// b0ybyaya0bayy11 reports {6,8} behind {9,12}. The sort is what the walk
	// rests on and is skipped where the list is already in that order, which is
	// every expression that runs no probe and most texts of the ones that do.
	//
	// Leaving the offset where an unordered walk happened to leave it would
	// leave it above where the rule puts it, and above is the side that
	// releases text rather than the side that holds it.
	// Test_MustRegexp_retainIsAFixedPointOfTheRule holds this to the rule and
	// Test_MustRegexp_findIsLinear holds it to the text.
	byStart := func(a, b Span) int { return a.Start - b.Start }
	if !slices.IsSortedFunc(spans, byStart) {
		slices.SortFunc(spans, byStart)
	}

	retain := p.retain(src)
	for i := len(spans) - 1; i >= 0; i-- {
		if s := spans[i]; s.End == len(src) || s.End > retain {
			retain = min(retain, s.Start)
		}
	}
	return spans, retain
}

// retain returns where src stops being settled for this expression.
//
// A match no wider than width bytes and beginning before len(src)-width ends
// before len(src) does, so the text it is made of is all here and nothing
// appended to src reaches it. The bound is what is subtracted rather than one
// less, which also settles the other way a match can move: an expression
// closing on $ or \b matches at the end of the text and stops matching once
// text follows, and the last width bytes are exactly where such a match can
// begin.
//
// Matches are found from the left and each carries on from where the one in
// front of it ended, so a match settled this way cannot be moved by one behind
// it either: every match in front of a settled one is settled as well.
func (p *regexpPattern) retain(src string) int {
	if !p.streams {
		return 0
	}

	settled := 0
	if p.width != regexpUnbounded {
		settled = max(0, len(src)-p.width)
	}

	// The literal an expression opens with settles the text in front of the
	// first place that literal could stand, whatever the expression does
	// behind it: a match carries the literal at its own start, so a text
	// carrying it nowhere carries no match anywhere, and one carrying it late
	// carries none earlier. It is the whole of what an expression with no
	// ceiling on its width can settle, and it is what keeps such a pattern from
	// holding a stream that has nothing of its in it at all.
	if p.literal != "" {
		opens := p.literalTail.start(src)
		if i := strings.Index(src, p.literal); i >= 0 {
			opens = min(opens, i)
		}
		settled = max(settled, opens)
	}
	return settled
}

func (p *regexpPattern) find(src string) []Span {
	// The submatch offsets are read only where a group is named, and asking
	// for them costs a slice a match: this walk is what a caller pays over a
	// line holding no value.
	var locs [][]int
	if len(p.mask) > 0 {
		locs = p.re.FindAllStringSubmatchIndex(src, -1)
	} else {
		locs = p.re.FindAllStringIndex(src, -1)
	}
	if len(locs) == 0 {
		return nil
	}

	var spans []Span

	// last is the span reported furthest along, which is the one most recently
	// reported: the walk below only moves forward. What it is for is the
	// candidate whose match cannot reach past it — a Masker merges what
	// overlaps, so such a match is in the output already and trying for it buys
	// nothing. Without that, an expression matching everywhere would be run
	// once per character of a text it matches the whole of.
	var last Span

	add := func(s Span) {
		if s.Start >= s.End {
			return // an empty span is a span a Masker ignores
		}
		if last.Start <= s.Start && s.End <= last.End {
			return // already covered by what stands furthest along
		}
		// A span overlapping the one before it is widened into it rather than
		// reported beside it, which is the same thing to a Masker and is the
		// difference between one span and one per character where matches
		// stand a character apart.
		//
		// Not where the expression reads the text in front of a match. A window
		// over part of a text has no text in front of its own beginning, so a
		// match beginning there is one this pattern may be wrong about and a
		// Masker drops it; widening a value that is really here into one that
		// may not be would have the two dropped together.
		if n := len(spans); p.coalesces && n > 0 && spans[n-1].Start <= s.Start && s.Start < spans[n-1].End {
			spans[n-1].End = max(spans[n-1].End, s.End)
			s = spans[n-1]
		} else {
			spans = append(spans, s)
		}
		if s.End > last.End {
			last = s
		}
	}

	// report reads a match out of loc, whose offsets stand base bytes into
	// src, and whose own text begins at start.
	report := func(start, base int, loc []int) {
		if len(p.mask) == 0 {
			add(Span{Start: start, End: base + loc[1]})
			return
		}
		for _, i := range p.mask {
			s, e := loc[2*i], loc[2*i+1]
			if s < 0 { // the group took part in no match
				continue
			}
			add(Span{Start: base + s, End: base + e})
		}
	}

	for _, loc := range locs {
		report(loc[0], 0, loc)
		if !p.probes {
			continue
		}

		// Every position inside a match can begin a match of its own, and the
		// walk that found this one stepped over all of them. Positions outside
		// one cannot: a match beginning there would be the leftmost that walk
		// found rather than a match it passed over.
		for at := loc[0] + 1; at < loc[1]; at++ {
			// A match opens with the literal the expression opens with, so
			// where there is one the positions between its occurrences hold
			// nothing and are stepped over rather than tried.
			if p.literal != "" {
				j := strings.Index(src[at:], p.literal)
				if j < 0 || at+j >= loc[1] {
					break
				}
				at += j
			}
			if !utf8.RuneStart(src[at]) {
				continue // no match begins inside a rune
			}
			if last.Start <= at && p.reachFrom(src, at) <= last.End {
				continue
			}
			_, w := utf8.DecodeLastRuneInString(src[:at])
			var m []int
			if len(p.mask) > 0 {
				m = p.after.FindStringSubmatchIndex(src[at-w:])
			} else {
				m = p.after.FindStringIndex(src[at-w:])
			}
			if m == nil {
				continue
			}
			report(at, at-w, m)
		}
	}
	return spans
}

// reachFrom returns the furthest a match beginning at src[at] can end.
func (p *regexpPattern) reachFrom(src string, at int) int {
	if p.width == regexpUnbounded {
		return len(src)
	}
	return min(at+p.width, len(src))
}

// regexpUnbounded is what regexpMaxWidth reports for an expression admitting a
// match of any width. It is negative so that no width can be mistaken for it.
const regexpUnbounded = -1

// regexpMaxWidth returns the widest match re admits in bytes, or
// regexpUnbounded where it admits one of any width.
//
// The width is an upper bound. Overshooting settles less text than the exact
// bound would and never settles what is not settled, so where the exact width
// is out of reach — an operator this walk has not been written for — the answer
// is that the expression is unbounded.
//
// It is worth being exact about a class and about folding, rather than counting
// four bytes to the rune throughout, because an expression written to locate a
// credential is written in ASCII: [0-9a-f]{40} is forty bytes wide and not a
// hundred and sixty, and the difference is text a stream holds back on every
// write. Folding is where a rune widens without the expression saying so — k
// and the Kelvin sign fold together and are one byte and three — so the orbit
// is walked rather than assumed.
func regexpMaxWidth(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch,
		syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0

	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			w := runeWidth(r)
			if re.Flags&syntax.FoldCase != 0 {
				for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
					w = max(w, runeWidth(f))
				}
			}
			n += w
		}
		return n

	case syntax.OpCharClass:
		// The runes of a class are the ranges it admits, in pairs, with
		// negation already worked out into them by the parser. The widest
		// rune of a range is the one it closes on.
		n := 0
		for i := 1; i < len(re.Rune); i += 2 {
			n = max(n, runeWidth(re.Rune[i]))
		}
		return n

	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax

	case syntax.OpCapture, syntax.OpQuest:
		return regexpMaxWidth(re.Sub[0])

	case syntax.OpStar, syntax.OpPlus:
		return regexpUnbounded

	case syntax.OpRepeat:
		if re.Max < 0 {
			return regexpUnbounded
		}
		w := regexpMaxWidth(re.Sub[0])
		if w == regexpUnbounded {
			return regexpUnbounded
		}
		return regexpMulWidth(w, re.Max)

	case syntax.OpConcat:
		n := 0
		for _, sub := range re.Sub {
			w := regexpMaxWidth(sub)
			if w == regexpUnbounded {
				return regexpUnbounded
			}
			n = regexpAddWidth(n, w)
			if n == regexpUnbounded {
				return regexpUnbounded
			}
		}
		return n

	case syntax.OpAlternate:
		n := 0
		for _, sub := range re.Sub {
			w := regexpMaxWidth(sub)
			if w == regexpUnbounded {
				return regexpUnbounded
			}
			n = max(n, w)
		}
		return n
	}
	return regexpUnbounded
}

// runeWidth returns how many bytes UTF-8 writes r in, and the widest a rune is
// written in where r is no rune UTF-8 writes at all — which a character class
// can name, since a class is a range of code points and the surrogates lie
// inside one.
func runeWidth(r rune) int {
	if w := utf8.RuneLen(r); w > 0 {
		return w
	}
	return utf8.UTFMax
}

// regexpReadsBehind reports whether the meaning of a match of re turns on the
// text in front of it: \b and \B are decided by the character before a match, ^
// by that character under (?m) and by there being one at all otherwise, and \A
// by the same.
func regexpReadsBehind(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpBeginLine, syntax.OpBeginText:
		return true
	}
	return slices.ContainsFunc(re.Sub, regexpReadsBehind)
}

// regexpNoMaskGroup is what regexpMaskDistance reports for an expression naming
// no group "mask". It is apart from regexpUnbounded, which says there is such a
// group and no ceiling on how far into a match it stands.
const regexpNoMaskGroup = -2

// regexpMaskDistance returns the widest stretch of text that can stand between
// the beginning of a match and the beginning of a group named "mask" inside it.
//
// What it is for is the one place this package cannot read a match back from
// its own span: a group is redacted, the match around it is not, and what
// decides the group is where the match began. A stream hands a pattern a window
// opening LookBehind bytes in front of the text still to be written out, so a
// group standing further into a match than that is a group decided by text
// outside the window — and there is nothing in the window to say the match was
// never there.
func regexpMaskDistance(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpCapture:
		d := regexpMaskDistance(re.Sub[0])
		if re.Name == "mask" && d == regexpNoMaskGroup {
			return 0
		}
		return d

	case syntax.OpConcat:
		// at is how far into this concatenation the next branch can begin,
		// which is what a group inside that branch stands behind.
		widest, at := regexpNoMaskGroup, 0
		for _, sub := range re.Sub {
			d := regexpMaskDistance(sub)
			if d != regexpNoMaskGroup {
				if d == regexpUnbounded || at == regexpUnbounded {
					return regexpUnbounded
				}
				if n := regexpAddWidth(at, d); n == regexpUnbounded {
					return regexpUnbounded
				} else {
					widest = max(widest, n)
				}
			}
			if at != regexpUnbounded {
				at = regexpAddWidth(at, regexpMaxWidth(sub))
			}
		}
		return widest

	case syntax.OpAlternate:
		widest := regexpNoMaskGroup
		for _, sub := range re.Sub {
			d := regexpMaskDistance(sub)
			if d == regexpUnbounded {
				return regexpUnbounded
			}
			widest = max(widest, d)
		}
		return widest

	case syntax.OpQuest:
		return regexpMaskDistance(re.Sub[0])

	case syntax.OpStar, syntax.OpPlus:
		if regexpMaskDistance(re.Sub[0]) == regexpNoMaskGroup {
			return regexpNoMaskGroup
		}
		return regexpUnbounded

	case syntax.OpRepeat:
		d := regexpMaskDistance(re.Sub[0])
		if d == regexpNoMaskGroup || re.Max == 0 {
			// A repetition of nothing writes nothing, so a group under one
			// takes part in no match and stands nowhere.
			return regexpNoMaskGroup
		}
		if d == regexpUnbounded || re.Max < 0 {
			return regexpUnbounded
		}
		// The group can stand in the last repetition, with every one in front
		// of it written out at its widest.
		return regexpAddWidth(regexpMulWidth(regexpMaxWidth(re.Sub[0]), re.Max-1), d)
	}
	return regexpNoMaskGroup
}

// regexpWidthLimit is the width past which regexpMaxWidth stops counting and
// calls an expression unbounded. Nested repetitions multiply, and an expression
// wide enough to overflow the count would otherwise report a width that wraps
// to a small one and settle text that is not settled. A gibibyte is far above
// any expression written to locate a credential and far below where the
// arithmetic goes wrong.
const regexpWidthLimit = 1 << 30

// regexpAddWidth returns a+b, or regexpUnbounded where either is unbounded or
// the sum passes regexpWidthLimit.
func regexpAddWidth(a, b int) int {
	if a == regexpUnbounded || b == regexpUnbounded {
		return regexpUnbounded
	}
	if n := a + b; n <= regexpWidthLimit {
		return n
	}
	return regexpUnbounded
}

// regexpMulWidth returns w*n, or regexpUnbounded where the product passes
// regexpWidthLimit.
func regexpMulWidth(w, n int) int {
	if w == regexpUnbounded {
		return regexpUnbounded
	}
	if w == 0 || n <= 0 {
		return 0
	}
	if n > regexpWidthLimit/w {
		return regexpUnbounded
	}
	return w * n
}
