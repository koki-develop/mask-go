// Package conformance holds the one statement of what this library does: a
// corpus of cases, each an input and the output it masks to, driven through
// every property masking must have.
//
// Nothing here reaches into the library. The package imports mask as a caller
// does, so what the corpus states is what a user of the module can observe, and
// the compiler rules out any shortcut through an unexported name.
//
// Every file here is a _test.go file, the package holds no other kind, and it is
// therefore never built into the module a caller imports. What would otherwise
// be an implementation file is one whose declarations the tests beside them
// read.
//
// This file is the notation the corpus is written in.
package conformance

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/koki-develop/mask-go"
)

// A case states what it masks to as marked text: the output of Mask with every
// redacted value written as «pattern-name».
//
// Writing the expectation this way is what makes it reviewable. A line of
// asterisks says nothing a reader can check — nobody counts forty of them, and
// nothing in it says which pattern fired — and a line that quotes the value back
// says no more, since checking it means comparing two long strings character by
// character.
//
// What is left is what can be read: the name of the pattern, and the text around
// the redaction. Where a redaction ends shows in what survives beside it, so a
// scan that stops two characters short of a token reads as
// «github-token»yz rather than as one long string differing from another
// somewhere.
const (
	markOpen  = '«'
	markClose = '»'
)

// marked is marked text taken apart: the literal text between the marks, and
// the pattern named by each mark. parts is always one longer than names.
type marked struct {
	parts []string
	names []string
}

// parseMarked reads marked text.
//
// The literal text is carried over one byte at a time rather than rune by rune:
// a corpus case may hold text that is not valid UTF-8, and decoding a rune from
// it would replace the byte with U+FFFD and quietly change what the case says.
func parseMarked(s string) (marked, error) {
	var m marked
	var part strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch r {
		case markClose:
			return marked{}, fmt.Errorf("a mark closes at byte %d without having opened", i)
		case markOpen:
			rest := s[i+size:]
			j := strings.IndexRune(rest, markClose)
			if j < 0 {
				return marked{}, fmt.Errorf("the mark opening at byte %d never closes", i)
			}
			name := rest[:j]
			switch {
			case name == "":
				return marked{}, fmt.Errorf("the mark at byte %d names no pattern", i)
			case strings.ContainsRune(name, markOpen):
				return marked{}, fmt.Errorf("the mark opening at byte %d opens another", i)
			}
			m.parts = append(m.parts, part.String())
			m.names = append(m.names, name)
			part.Reset()
			i += size + j + utf8.RuneLen(markClose)
		default:
			part.WriteString(s[i : i+size])
			i += size
		}
	}
	m.parts = append(m.parts, part.String())
	return m, nil
}

// render returns the marked text with the mark before each part replaced by
// what redact returns for it.
func (m marked) render(redact func(i int) string) string {
	var b strings.Builder
	for i, part := range m.parts {
		if i > 0 {
			b.WriteString(redact(i - 1))
		}
		b.WriteString(part)
	}
	return b.String()
}

// restore returns the text the marks were made from: the literal text with each
// value back in the place its mark holds.
func (m marked) restore(values []string) (string, error) {
	if len(values) != len(m.names) {
		return "", fmt.Errorf("the text holds %d mark(s) and %d value(s) were given", len(m.names), len(values))
	}
	return m.render(func(i int) string { return values[i] }), nil
}

// bounds returns where each redaction begins and ends in the text the marked
// text was made from.
//
// The count is checked as restore checks it: the values come from masking now
// and the marks from what the corpus holds, so a corpus that has fallen behind
// gives fewer of one than the other. Indexing on regardless would read past the
// parts and take the package down with it, where what is wanted is the failure
// that says to run -update.
func (m marked) bounds(values []string) ([][2]int, error) {
	if len(values) != len(m.names) {
		return nil, fmt.Errorf("the text holds %d mark(s) and %d value(s) were given", len(m.names), len(values))
	}
	out := make([][2]int, 0, len(values))
	pos := 0
	for i, value := range values {
		pos += len(m.parts[i])
		out = append(out, [2]int{pos, pos + len(value)})
		pos += len(value)
	}
	return out, nil
}

// fill returns what Mask must return under Fill(r): one r for every rune of the
// value that was redacted, which is where a redaction that miscounts multi-byte
// text shows.
func (m marked) fill(values []string, r rune) string {
	return m.render(func(i int) string {
		return strings.Repeat(string(r), utf8.RuneCountInString(values[i]))
	})
}

// fixed returns what Mask must return under Fixed(s).
func (m marked) fixed(s string) string {
	return m.render(func(int) string { return s })
}

// markingRedactor writes «pattern-name» in place of a value, which is the
// notation itself, and records the values it was handed so that what every
// other redactor must give can be worked out from them.
//
// A Masker holding one is used by a single goroutine at a time; the properties
// that drive many at once build their own.
type markingRedactor struct {
	values []string
}

func (r *markingRedactor) Redact(m mask.Match) string {
	r.values = append(r.values, m.Value)
	return string(markOpen) + m.Pattern.Name() + string(markClose)
}

// markRedactor writes the notation and keeps nothing, so it can be shared
// between goroutines the way a caller shares a Masker. markingRedactor records
// what it was handed as well, and cannot.
var markRedactor = mask.NewRedactor(func(m mask.Match) string {
	return string(markOpen) + m.Pattern.Name() + string(markClose)
})

// markReplacer is what textWithoutMarks rewrites the mark runes with. The runes
// taken out are read off markOpen and markClose so that the two cannot come
// apart: a notation written with different runes tomorrow is a helper that takes
// those runes out instead.
//
// Two bytes go in where two bytes come out, and that is a requirement rather
// than a nicety. Both mark runes are two bytes, and what reads this is a fuzz
// target driving WithMaxRetained, whose limit is a count of bytes —
// stream.go holds a stream to len(src)-s.out > s.maxRetained. A replacement one
// byte shorter would leave an input the fuzzer built to run past a limit
// stopping short of it, and a stream that never gives up exercises nothing that
// target is for. So the replacements are counted, and
// Test_textWithoutMarks_preservesLength holds them to it.
//
// Brackets rather than anything less legible: text carrying a mark keeps its
// shape and reads as what it was in a failure message.
var markReplacer = strings.NewReplacer(string(markOpen), "<<", string(markClose), ">>")

// textWithoutMarks returns src with the mark runes rewritten, so that marked
// text made out of it holds the marks a redactor wrote and no others.
//
// parseMarked reads the marks back out of masked text, which it can only do
// while every mark rune in that text is one a redactor put there. A mark rune
// standing in the text itself is indistinguishable from one, and there are two
// ways that goes wrong.
//
// The loud way is a mark the parse cannot read — one that never closes, one
// that closes without opening, one opening another, one naming nothing — and
// what is then reported is the parse rather than anything about masking. That
// is what a fuzzer found.
//
// The quiet way is worse and is the reason this helper exists. Text carrying a
// well-formed mark that names a real pattern parses, so a check reading the
// name back is handed the text's own mark and cannot tell it from a redactor's.
// givingUp.check asks whether any mark was made and whether the last names a
// pattern it was given; text holding «stripe-secret-key» answers both for a
// stream that made no mark at all, and a give-up attributed to nothing would
// pass. A parse error fails the run and gets fixed; this reports nothing ever.
//
// A test driven from the corpus needs none of this. A case's in field may not
// hold either rune, which corpus_test.go holds it to, so masked text built
// from one carries only what a redactor wrote. A fuzz target has no such
// footing: the corpus seeds it, but a fuzzer mutates bytes, and « is 0xC2 0xAB
// — two bytes a mutation can arrive at from anything. So the invariant the
// corpus states for its own cases is stated here for generated text, and a
// fuzz target whose check reads marks back calls this on what it was handed.
//
// Rewriting rather than turning the input away, because the mark runes belong
// to this package's notation and not to anything the library does. To a scan
// they are two bytes of ordinary text, which the corpus and the seeds already
// carry in quantity; what the input was generated to reach is the masking, and
// a target that returned early here would leave the fuzzer spending its budget
// on inputs that check nothing at all.
func textWithoutMarks(src string) string {
	return markReplacer.Replace(src)
}

// maskMarked masks src, returning the marked text and the values that were
// redacted, in order.
func maskMarked(patterns []mask.Pattern, src string) (string, []string) {
	r := &markingRedactor{}
	out := mask.New(mask.WithPatterns(patterns...), mask.WithRedactor(r)).Mask(src)
	return out, r.values
}

// A corpus file is text, and the text a case carries may hold bytes text cannot
// show: a control character, a byte that is not valid UTF-8, a space at either
// end that trimming would eat. Those are written with the escapes below, and
// everything else stands for itself, so that a line holding a credential reads
// as the line it stands for.
//
// decodeText reads that escaping, and encodeText writes it.
func decodeText(s string) (string, error) {
	if !strings.ContainsRune(s, '\\') {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			i++
			continue
		}
		i++
		if i == len(s) {
			return "", fmt.Errorf("the text ends with a lone backslash")
		}
		switch s[i] {
		case '\\':
			b.WriteByte('\\')
			i++
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case 'x':
			if i+3 > len(s) {
				return "", fmt.Errorf(`\x at byte %d is not followed by two hexadecimal digits`, i-1)
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return "", fmt.Errorf(`\x%s at byte %d is not two hexadecimal digits`, s[i+1:i+3], i-1)
			}
			b.WriteByte(byte(v))
			i += 3
		default:
			return "", fmt.Errorf(`unknown escape \%c at byte %d`, s[i], i-1)
		}
	}
	return b.String(), nil
}

func encodeText(s string) string {
	// A field is read with the space around it trimmed, and trimming takes any
	// space Unicode calls one, not only the ASCII one. The runes at either end
	// are written out byte by byte where they are such a space, so that text
	// beginning or ending with one survives being read back.
	leading, trailing := 0, len(s)
	if r, size := utf8.DecodeRuneInString(s); unicode.IsSpace(r) {
		leading = size
	}
	if r, size := utf8.DecodeLastRuneInString(s); unicode.IsSpace(r) {
		trailing = len(s) - size
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\\':
			b.WriteString(`\\`)
			i++
		case c == '\n':
			b.WriteString(`\n`)
			i++
		case c == '\r':
			b.WriteString(`\r`)
			i++
		case c == '\t':
			b.WriteString(`\t`)
			i++
		case c < 0x20 || c == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, c)
			i++
		case i < leading || i >= trailing:
			fmt.Fprintf(&b, `\x%02x`, c)
			i++
		case c < utf8.RuneSelf:
			b.WriteByte(c)
			i++
		default:
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				fmt.Fprintf(&b, `\x%02x`, c)
				i++
				continue
			}
			b.WriteString(s[i : i+size])
			i += size
		}
	}
	return b.String()
}

func Test_parseMarked(t *testing.T) {
	tests := []struct {
		name  string
		src   string
		parts []string
		names []string
	}{
		{
			name:  "no mark",
			src:   "nothing to redact",
			parts: []string{"nothing to redact"},
		},
		{
			name:  "one mark",
			src:   "GITHUB_TOKEN=«github-token»",
			parts: []string{"GITHUB_TOKEN=", ""},
			names: []string{"github-token"},
		},
		{
			name:  "the whole text",
			src:   "«jwt»",
			parts: []string{"", ""},
			names: []string{"jwt"},
		},
		{
			name:  "two marks",
			src:   "a«p»b«q»c",
			parts: []string{"a", "b", "c"},
			names: []string{"p", "q"},
		},
		{
			name:  "marks that touch",
			src:   "«p»«q»",
			parts: []string{"", "", ""},
			names: []string{"p", "q"},
		},
		{
			name:  "multi-byte text around a mark",
			src:   "日本語«p»日本語",
			parts: []string{"日本語", "日本語"},
			names: []string{"p"},
		},
		{
			name:  "text that is not valid utf-8 is carried over byte for byte",
			src:   "\xff\xfe",
			parts: []string{"\xff\xfe"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMarked(tt.src)
			if err != nil {
				t.Fatalf("parseMarked(%q) failed: %v", tt.src, err)
			}
			if !slices.Equal(got.parts, tt.parts) {
				t.Errorf("parts = %q, want %q", got.parts, tt.parts)
			}
			if !slices.Equal(got.names, tt.names) {
				t.Errorf("names = %q, want %q", got.names, tt.names)
			}
		})
	}
}

func Test_parseMarked_malformed(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{name: "a mark that never closes", src: "«p"},
		{name: "a mark that closes without opening", src: "abc»"},
		{name: "a mark opening another", src: "«p«q»»"},
		{name: "a mark naming no pattern", src: "«»"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseMarked(tt.src); err == nil {
				t.Errorf("parseMarked(%q) succeeded, want an error", tt.src)
			}
		})
	}
}

func Test_textWithoutMarks(t *testing.T) {
	// What the helper owes: text a redactor can mark without parseMarked
	// reading any of it as a mark. The inputs are the shapes
	// Test_parseMarked_malformed writes out, plus the three a fuzzer arrived at,
	// so that a helper which stopped taking a rune out fails here rather than
	// in a fuzz run days later.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{name: "text with no mark at all", src: "abc", want: "abc"},
		{name: "empty text", src: "", want: ""},
		{name: "a mark that never closes", src: "«p", want: "<<p"},
		{name: "a mark that closes without opening", src: "abc»", want: "abc>>"},
		{name: "a mark opening another", src: "«p«q»»", want: "<<p<<q>>>>"},
		{name: "a mark naming no pattern", src: "«»", want: "<<>>"},
		{name: "an opening mark inside the text", src: "0«0000000000", want: "0<<0000000000"},
		{name: "an opening mark at the start", src: "«0000000000", want: "<<0000000000"},
		{name: "a closing mark at the start", src: "»0000000000", want: ">>0000000000"},
		{
			// The shape parseMarked reads without complaint, and so the one a
			// check reading a name back cannot tell from a redactor's mark.
			// textWithoutMarks's own doc says why that is the worse of the two.
			name: "a well-formed mark naming a real pattern",
			src:  "«stripe-secret-key»",
			want: "<<stripe-secret-key>>",
		},
		{name: "text that is not valid utf-8", src: "\xff\xfe", want: "\xff\xfe"},
		{
			// The bytes « is written from, standing apart. Neither is a mark,
			// and neither may be rewritten as one.
			name: "the bytes of a mark rune written separately",
			src:  "\xc2z\xabz",
			want: "\xc2z\xabz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := textWithoutMarks(tt.src)
			if got != tt.want {
				t.Errorf("textWithoutMarks(%q) = %q, want %q", tt.src, got, tt.want)
			}
			if strings.ContainsRune(got, markOpen) || strings.ContainsRune(got, markClose) {
				t.Errorf("textWithoutMarks(%q) = %q, which still holds a mark rune", tt.src, got)
			}
		})
	}
}

func Test_textWithoutMarks_preservesLength(t *testing.T) {
	// What markReplacer says it is for. The target reading it drives
	// WithMaxRetained, whose limit counts bytes, so a rewrite that shortened
	// the text would take an input the fuzzer built to run past a limit and
	// leave it short of one — and a stream that never gives up says nothing
	// about giving up.
	//
	// Both mark runes are asked about, and so is the length of what stands in
	// for each: a replacement of any other width fails here rather than in a
	// fuzz run that quietly stops reaching the give-up.
	for _, r := range []rune{markOpen, markClose} {
		t.Run(string(r), func(t *testing.T) {
			if got, want := len(textWithoutMarks(string(r))), utf8.RuneLen(r); got != want {
				t.Errorf("textWithoutMarks(%q) is %d byte(s), want %d", string(r), got, want)
			}
		})
	}

	for _, src := range []string{"", "abc", "«p", "abc»", "«p«q»»", "«»", "0«0000000000", "»0000000000", "\xff\xfe", "日本語«x»"} {
		t.Run(src, func(t *testing.T) {
			if got, want := len(textWithoutMarks(src)), len(src); got != want {
				t.Errorf("textWithoutMarks(%q) is %d byte(s), want %d", src, got, want)
			}
		})
	}
}

func Test_textWithoutMarks_leavesMarkedTextParsable(t *testing.T) {
	// The property the helper exists for, stated end to end: whatever it returns
	// can carry a mark and be read back, with the one mark read being the one
	// written.
	//
	// A mark is put on either side of the text rather than on one, because the
	// two adjacencies are different bytes. Masked text carries a mark against
	// what stood before it as well as against what stands after, and text
	// ending in 0xC2 against an opening mark is the byte pair a rewrite could
	// have made a mark out of had it left a lead byte behind.
	mark := string(markOpen) + "a-pattern" + string(markClose)
	sources := []string{
		"«p", "abc»", "«p«q»»", "«»", "0«0000000000", "»0000000000",
		"«stripe-secret-key»", "\xff\xfe", "\xc2", "\xc2\xc2", "日本語«x»",
	}
	for _, src := range sources {
		t.Run(src, func(t *testing.T) {
			for _, text := range []string{mark + textWithoutMarks(src), textWithoutMarks(src) + mark} {
				m, err := parseMarked(text)
				if err != nil {
					t.Fatalf("parseMarked(%q) failed: %v", text, err)
				}
				if len(m.names) != 1 || m.names[0] != "a-pattern" {
					t.Errorf("parseMarked(%q) read names %v, want one mark naming a-pattern", text, m.names)
				}
			}
		})
	}
}

func Test_marked_renders(t *testing.T) {
	m, err := parseMarked("a«p»b«q»e")
	if err != nil {
		t.Fatalf("parseMarked failed: %v", err)
	}
	values := []string{"日本", "cd"}

	if got, err := m.restore(values); err != nil || got != "a日本bcde" {
		t.Errorf("restore() = %q, %v, want %q", got, err, "a日本bcde")
	}
	if got, err := m.bounds(values); err != nil || len(got) != 2 || got[0] != [2]int{1, 7} || got[1] != [2]int{8, 10} {
		t.Errorf("bounds() = %v, %v, want the two redactions of %q", got, err, "a日本bcde")
	}
	if got, want := m.fill(values, '*'), "a**b**e"; got != want {
		t.Errorf("fill('*') = %q, want %q", got, want)
	}
	if got, want := m.fill(values, '#'), "a##b##e"; got != want {
		t.Errorf("fill('#') = %q, want %q", got, want)
	}
	if got, want := m.fixed("[R]"), "a[R]b[R]e"; got != want {
		t.Errorf("fixed(\"[R]\") = %q, want %q", got, want)
	}
	if got, want := m.fixed(""), "abe"; got != want {
		t.Errorf("fixed(\"\") = %q, want %q", got, want)
	}
}

func Test_marked_countsTheValues(t *testing.T) {
	m, err := parseMarked("a«p»b")
	if err != nil {
		t.Fatalf("parseMarked failed: %v", err)
	}
	for _, values := range [][]string{nil, {"x", "y"}} {
		if _, err := m.restore(values); err == nil {
			t.Errorf("restore(%q) succeeded, want an error", values)
		}
		if _, err := m.bounds(values); err == nil {
			t.Errorf("bounds(%q) succeeded, want an error", values)
		}
	}
}

func Test_maskMarked(t *testing.T) {
	patterns := patternSets["github-token"]
	src := "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz done"

	out, values := maskMarked(patterns, src)
	if want := "GITHUB_TOKEN=«github-token» done"; out != want {
		t.Errorf("maskMarked() = %q, want %q", out, want)
	}
	if want := []string{"ghp_0123456789abcdefghijklmnopqrstuvwxyz"}; !slices.Equal(values, want) {
		t.Errorf("maskMarked() recorded %q, want %q", values, want)
	}
}

func Test_decodeText(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{name: "plain text", src: "abcdef", want: "abcdef"},
		{name: "a newline", src: `a\nb`, want: "a\nb"},
		{name: "a carriage return", src: `a\rb`, want: "a\rb"},
		{name: "a tab", src: `a\tb`, want: "a\tb"},
		{name: "a backslash", src: `a\\b`, want: `a\b`},
		{name: "a byte", src: `a\x00b`, want: "a\x00b"},
		{name: "a byte that is not valid utf-8", src: `\xff\xfe`, want: "\xff\xfe"},
		{name: "a space written out", src: `\x20a\x20`, want: " a "},
		{name: "multi-byte text stands for itself", src: "日本語", want: "日本語"},
		{name: "empty", src: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeText(tt.src)
			if err != nil {
				t.Fatalf("decodeText(%q) failed: %v", tt.src, err)
			}
			if got != tt.want {
				t.Errorf("decodeText(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_decodeText_malformed(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{name: "a lone backslash", src: `abc\`},
		{name: "an unknown escape", src: `a\qb`},
		{name: "a short byte escape", src: `a\x0`},
		{name: "a byte escape that is not hexadecimal", src: `a\xzzb`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeText(tt.src); err == nil {
				t.Errorf("decodeText(%q) succeeded, want an error", tt.src)
			}
		})
	}
}

func Test_encodeText(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{name: "plain text", src: "abcdef", want: "abcdef"},
		{name: "a newline", src: "a\nb", want: `a\nb`},
		{name: "a backslash", src: `a\b`, want: `a\\b`},
		{name: "a control byte", src: "a\x00b", want: `a\x00b`},
		{name: "a byte that is not valid utf-8", src: "\xff\xfe", want: `\xff\xfe`},
		{name: "a space in the middle stands for itself", src: "a b", want: "a b"},
		{name: "a space at either end is written out", src: " a ", want: `\x20a\x20`},
		{name: "one space alone is written out", src: " ", want: `\x20`},
		{name: "a space unicode calls one is written out too", src: " a ", want: `\xc2\xa0a\xc2\xa0`},
		{name: "such a space in the middle stands for itself", src: "a b", want: "a b"},
		{name: "multi-byte text stands for itself", src: "日本語", want: "日本語"},
		{name: "the notation is left alone", src: "«p»", want: "«p»"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodeText(tt.src); got != tt.want {
				t.Errorf("encodeText(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

// FuzzText holds the escaping to reading back what it wrote. A corpus file is
// rewritten by the -update flag, so text that does not survive the round trip
// would rewrite a case into a different one.
func FuzzText(f *testing.F) {
	f.Add("abcdef")
	f.Add("")
	f.Add(" a ")
	f.Add("a\nb")
	f.Add("\xff\xfe")
	f.Add("日本語")
	f.Add(`a\b`)
	f.Add("«p»")
	f.Add(" ")

	f.Fuzz(func(t *testing.T, src string) {
		encoded := encodeText(src)
		if strings.ContainsAny(encoded, "\n\r") {
			t.Fatalf("encodeText(%q) = %q, which no longer fits on one line", src, encoded)
		}
		if trimmed := strings.TrimSpace(encoded); trimmed != encoded {
			t.Fatalf("encodeText(%q) = %q, which trimming changes to %q", src, encoded, trimmed)
		}
		got, err := decodeText(encoded)
		if err != nil {
			t.Fatalf("decodeText(%q) failed: %v", encoded, err)
		}
		if got != src {
			t.Fatalf("decodeText(encodeText(%q)) = %q", src, got)
		}
	})
}
