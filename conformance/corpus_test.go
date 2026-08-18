// The corpus: the files under testdata, and how a case is read from one and
// written back to it.
//
// A case is two lines an author writes — what it is called, and the text to mask
// — and one line generated: what Mask returns for it, with every redacted value
// written as «pattern-name». The generated line is what a reviewer reads, and it
// is generated so that a case costs almost nothing to add and the corpus can be
// as wide as the behaviour is. It is always the output itself, whether or not
// anything was redacted: a case that says a word instead of what came back is
// one a reader has to take on trust.
//
// A generated expectation would be worth little if regenerating it could bless
// anything, and what keeps it honest is that it can be read. A redaction shows
// as the name of the pattern that made it, in the place it was made, with the
// text around it intact; a scan that stops two characters short of a token
// leaves those two characters sitting beside the mark, and one that reaches too
// far eats a character of the text that was there. Both are a line to read in a
// diff rather than two long strings to compare.

package conformance

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/koki-develop/mask-go"
)

var update = flag.Bool("update", false, "rewrite the out field of every corpus case from what the library does now")

// corpusDir is where the files live. It is the one place to look for what this
// library does.
const corpusDir = "testdata"

// corpusCase is one case: what an author wrote, and what was generated for it.
type corpusCase struct {
	file  string // the file it was read from
	line  int    // the line its case field is on
	name  string // what the case is called, unique within its file
	set   string // the entry of patternSets it is masked with
	in    string // the text to mask
	out   string // that text masked, with every redaction marked, generated
	reads bool   // whether the patterns locate values in the text they are handed

	hasIn       bool
	hasOut      bool
	insertAfter int // index of the last hand-written field line of the case
	outLine     int // index of the out line the file already holds, or -1
}

// id names the case in a failure.
func (c *corpusCase) id() string { return fmt.Sprintf("%s:%d %s", c.file, c.line, c.name) }

// subtest names the case in a t.Run path. A name is unique within its file and
// not across the corpus, so the file is part of it: without that, Go renames the
// second case of a repeated name to name#01, and a -run aimed at a failure picks
// out whichever of them came first.
func (c *corpusCase) subtest() string { return c.file + "/" + c.name }

// patterns returns the set the case is masked with.
func (c *corpusCase) patterns() []mask.Pattern { return patternSets[c.set] }

// requireOut fails where the case has no generated line yet.
//
// Every check that reads one must say so rather than read the zero value:
// parseMarked succeeds on empty text and reports no redaction, so a case still
// waiting for -update would otherwise pass for a case that redacts nothing —
// and count as one where its pattern locates nothing.
func (c *corpusCase) requireOut(t testing.TB) {
	t.Helper()

	if !c.hasOut {
		t.Fatalf("%s has no out field; run go test ./conformance -update and review what it writes", c.id())
	}
}

// names returns the pattern each redaction of the case is attributed to, in
// order. It reads them from the generated line, so a case that redacts nothing
// names nothing.
func (c *corpusCase) names(t testing.TB) []string {
	t.Helper()

	c.requireOut(t)
	m, err := parseMarked(c.out)
	if err != nil {
		t.Fatalf("%s: the out field is not marked text: %v", c.id(), err)
	}
	return m.names
}

// corpusFile is a file of cases, kept with the lines it was read from so that
// -update rewrites what it generated and leaves everything else as it was.
type corpusFile struct {
	name  string
	path  string
	lines []string
	cases []*corpusCase
	field map[int]fieldAt // which case and field each line carries
}

// fieldAt is what a line of a file holds: the field of the case it belongs to,
// or, where it belongs to no case, the directive it sets and what it says.
type fieldAt struct {
	c     *corpusCase // nil for a directive standing between cases
	key   string
	value string // what the directive says; a field is written from its case
}

const (
	fieldCase     = "case"
	fieldIn       = "in"
	fieldOut      = "out"
	fieldPatterns = "patterns"
	fieldSpans    = "spans"
)

func parseCorpusFile(name string, data []byte) (*corpusFile, error) {
	f := &corpusFile{name: name, path: filepath.Join(corpusDir, name), field: map[int]fieldAt{}}
	if len(data) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
		return nil, fmt.Errorf("%s does not end with a newline", name)
	}
	text := strings.TrimSuffix(string(data), "\n")
	if text != "" {
		f.lines = strings.Split(text, "\n")
	}

	// What a case that says nothing about them is read with: what the last
	// directive above it said, and these until one does. A file of one kind of
	// value names its pattern set once rather than in every case, and a file
	// whose patterns report spans of their own says so once as well.
	set, reads := "default", true

	var cur *corpusCase
	var fields map[string]bool // the fields the case being read has already given
	seen := map[string]bool{}
	for i, line := range f.lines {
		at := fmt.Sprintf("%s:%d", name, i+1)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			// A blank line ends a case. It is what tells a field belonging to
			// the case above from one standing on its own, which patterns and
			// spans do: without it, a set named between two cases would read as
			// a field of the case before it and silently mask the case after it
			// with whatever came earlier.
			cur, fields = nil, nil
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return nil, fmt.Errorf("%s: %q is not a field", at, trimmed)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)

		if key == fieldCase {
			if value == "" {
				return nil, fmt.Errorf("%s: the case has no name", at)
			}
			if seen[value] {
				return nil, fmt.Errorf("%s: a case called %q is already in this file", at, value)
			}
			seen[value] = true
			cur = &corpusCase{
				file: name, line: i + 1, name: value,
				set: set, reads: reads, insertAfter: i, outLine: -1,
			}
			fields = map[string]bool{fieldCase: true}
			f.cases = append(f.cases, cur)
			f.field[i] = fieldAt{c: cur, key: fieldCase}
			continue
		}

		if cur == nil {
			// Outside a case, what is set is what the cases below are read
			// with, which is what spares a file of one kind of value from
			// saying the same thing in every case.
			switch key {
			case fieldPatterns:
				if _, ok := patternSets[value]; !ok {
					return nil, fmt.Errorf("%s: no pattern set is called %q", at, value)
				}
				set = value
			case fieldSpans:
				found, err := parseSpans(value)
				if err != nil {
					return nil, fmt.Errorf("%s: the spans field: %w", at, err)
				}
				reads = found
			default:
				return nil, fmt.Errorf("%s: %q belongs to no case; a blank line above it ended the one before", at, key)
			}
			f.field[i] = fieldAt{key: key, value: value}
			continue
		}

		if fields[key] {
			// in and out were the only fields this was checked for, and a
			// second patterns or spans quietly won over the first, leaving the
			// case stating behaviour for a set its author did not name.
			return nil, fmt.Errorf("%s: the case already has a %s field", at, key)
		}
		fields[key] = true
		if key != fieldOut {
			cur.insertAfter = i
		}
		f.field[i] = fieldAt{c: cur, key: key}
		switch key {
		case fieldPatterns:
			if _, ok := patternSets[value]; !ok {
				return nil, fmt.Errorf("%s: no pattern set is called %q", at, value)
			}
			cur.set = value
		case fieldSpans:
			found, err := parseSpans(value)
			if err != nil {
				return nil, fmt.Errorf("%s: the spans field: %w", at, err)
			}
			cur.reads = found
		case fieldIn:
			in, err := decodeText(value)
			if err != nil {
				return nil, fmt.Errorf("%s: the in field: %w", at, err)
			}
			if strings.ContainsAny(in, string(markOpen)+string(markClose)) {
				return nil, fmt.Errorf("%s: the in field holds %c or %c, which the notation is built from", at, markOpen, markClose)
			}
			cur.in, cur.hasIn = in, true
		case fieldOut:
			cur.hasOut, cur.outLine = true, i
			out, err := decodeText(value)
			if err != nil {
				return nil, fmt.Errorf("%s: the out field: %w", at, err)
			}
			cur.out = out
		default:
			return nil, fmt.Errorf("%s: %q is not a field a case has", at, key)
		}
	}

	for _, c := range f.cases {
		if !c.hasIn {
			return nil, fmt.Errorf("%s:%d: the case %q has no in field", name, c.line, c.name)
		}
	}
	return f, nil
}

// parseSpans reads the spans field: whether the patterns of the case locate
// values in the text they are handed, which is what nearly every pattern does,
// or report spans of their own whatever they are handed.
//
// A pattern of the second kind states what no pattern of the first can — the
// spans a Masker must not trust — but the properties that follow a value around
// say nothing about it: it does not follow a value around. Masking it is not
// even idempotent, since the second pass reports the same offsets into a text
// that has changed under them. Those properties are held back for such a case,
// and only for such a case.
func parseSpans(value string) (bool, error) {
	switch value {
	case "found":
		return true, nil
	case "reported":
		return false, nil
	}
	return false, fmt.Errorf("it is %q, want found or reported", value)
}

// fieldValue returns what a field of a case is written as.
func fieldValue(c *corpusCase, key string) string {
	switch key {
	case fieldCase:
		return c.name
	case fieldIn:
		return encodeText(c.in)
	case fieldOut:
		return encodeText(c.out)
	case fieldPatterns:
		return c.set
	case fieldSpans:
		if c.reads {
			return "found"
		}
		return "reported"
	}
	return ""
}

// fieldLine returns the line a field is written on. The fields of a case are
// laid out to one column so that the text of every case begins in the same
// place, which is what makes a file of them read as a list rather than as prose.
//
// A field of empty text is written without the column, since the padding would
// leave whitespace at the end of the line. Anything that strips it — an editor,
// a hook — would then leave a file the round trip cannot reproduce and -update
// writes straight back.
func fieldLine(key, value string) string {
	return strings.TrimRight(fmt.Sprintf("%-5s %s", key+":", value), " ")
}

// render returns the file as it should be on disk: what was written by hand,
// laid out to one column, with what was generated for each case beside it.
//
// A generated line already in the file is rewritten where it stands rather than
// moved to a place of this function's choosing. Nothing a reader put in a case —
// a comment on the line above the generated one, most of all — is then shifted
// by a run of -update. Only a case that has no generated line yet gets one put
// after its last field.
func (f *corpusFile) render() []byte {
	var b strings.Builder
	for i, line := range f.lines {
		at, ok := f.field[i]
		if !ok {
			b.WriteString(line) // a comment or a blank line
			b.WriteString("\n")
			continue
		}
		if at.c == nil {
			b.WriteString(fieldLine(at.key, at.value)) // a directive
			b.WriteString("\n")
			continue
		}
		if at.key == fieldOut {
			if at.c.hasOut {
				b.WriteString(fieldLine(fieldOut, fieldValue(at.c, fieldOut)))
				b.WriteString("\n")
			}
			continue
		}
		b.WriteString(fieldLine(at.key, fieldValue(at.c, at.key)))
		b.WriteString("\n")
		if at.c.outLine < 0 && at.c.insertAfter == i && at.c.hasOut {
			b.WriteString(fieldLine(fieldOut, fieldValue(at.c, fieldOut)))
			b.WriteString("\n")
		}
	}
	return []byte(b.String())
}

// loadCorpus reads every file of the corpus. A file that does not parse is
// fatal rather than skipped: the corpus is the statement of behaviour, and a
// statement that cannot be read is not one that passes.
func loadCorpus(t testing.TB) []*corpusFile {
	t.Helper()

	names, err := filepath.Glob(filepath.Join(corpusDir, "*.txt"))
	if err != nil {
		t.Fatalf("reading %s: %v", corpusDir, err)
	}
	if len(names) == 0 {
		t.Fatalf("%s holds no corpus file", corpusDir)
	}
	slices.Sort(names)

	files := make([]*corpusFile, 0, len(names))
	for _, path := range names {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		f, err := parseCorpusFile(filepath.Base(path), data)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if len(f.cases) == 0 {
			t.Fatalf("%s holds no case", path)
		}
		files = append(files, f)
	}
	return files
}

// corpusCases returns every case of the corpus, across files.
func corpusCases(t testing.TB) []*corpusCase {
	t.Helper()

	var cases []*corpusCase
	for _, f := range loadCorpus(t) {
		cases = append(cases, f.cases...)
	}
	return cases
}

func Test_parseCorpusFile(t *testing.T) {
	data := []byte(`# a corpus file

patterns: github-token

case: a token
in:   GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz
out:  GITHUB_TOKEN=«github-token»

case: prose
in:   there is no credential in this sentence
out:  there is no credential in this sentence

case: a case of its own
patterns: jwt
spans: reported
in:   a\nb

spans: reported

case: after a directive of its own
in:   abc
`)

	f, err := parseCorpusFile("example.txt", data)
	if err != nil {
		t.Fatalf("parseCorpusFile failed: %v", err)
	}
	if len(f.cases) != 4 {
		t.Fatalf("read %d case(s), want 4", len(f.cases))
	}

	first := f.cases[0]
	if first.name != "a token" {
		t.Errorf("the first case is called %q", first.name)
	}
	if first.set != "github-token" {
		t.Errorf("the first case is masked with %q, want the set named before it", first.set)
	}
	if !first.hasOut || first.out != "GITHUB_TOKEN=«github-token»" {
		t.Errorf("the first case has out %q", first.out)
	}
	if !first.reads {
		t.Error("the first case names no spans field, so its patterns must be read as reading the text")
	}

	second := f.cases[1]
	if second.out != second.in {
		t.Errorf("the second case redacts nothing, so its out is its in; got %q", second.out)
	}
	if names := second.names(t); len(names) != 0 {
		t.Errorf("the second case redacts %v, want nothing", names)
	}

	third := f.cases[2]
	if third.set != "jwt" {
		t.Errorf("the third case is masked with %q, want the set it names itself", third.set)
	}
	if third.reads {
		t.Error("the third case says spans: reported")
	}
	if third.in != "a\nb" {
		t.Errorf("the third case has in %q, want the escape read", third.in)
	}
	if third.hasOut {
		t.Error("the third case has no out field to read")
	}

	// A directive between cases applies to the cases below it and to nothing
	// above it. A blank line is what ends a case, so the directive is not read
	// as a field of the case before.
	fourth := f.cases[3]
	if fourth.set != "github-token" {
		t.Errorf("the fourth case is masked with %q, want the set the file named", fourth.set)
	}
	if fourth.reads {
		t.Error("the fourth case comes under a directive saying spans: reported")
	}
	if third.set != "jwt" {
		t.Errorf("the directive below the third case changed it to %q", third.set)
	}
}

func Test_parseCorpusFile_malformed(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "a line that is not a field", data: "case: a\nin: b\nnonsense\n"},
		{name: "a case with no name", data: "case:\nin: b\n"},
		{name: "two cases with one name", data: "case: a\nin: b\n\ncase: a\nin: c\n"},
		{name: "a field before any case", data: "in: b\n"},
		{name: "a field belonging to no case", data: "case: a\nin: b\n\nin: c\n"},
		{name: "an unknown field", data: "case: a\nin: b\nwhat: c\n"},
		{name: "an unknown pattern set", data: "case: a\npatterns: nowhere\nin: b\n"},
		{name: "an unknown pattern set as a directive", data: "patterns: nowhere\ncase: a\nin: b\n"},
		{name: "no in field", data: "case: a\nout: b\n"},
		{name: "two in fields", data: "case: a\nin: b\nin: c\n"},
		{name: "two out fields", data: "case: a\nin: b\nout: b\nout: b\n"},
		{name: "two patterns fields", data: "case: a\npatterns: jwt\npatterns: github-token\nin: b\n"},
		{name: "two spans fields", data: "case: a\nspans: found\nspans: reported\nin: b\n"},
		{name: "a bad escape in in", data: "case: a\n" + `in: \q` + "\n"},
		{name: "a bad escape in out", data: "case: a\nin: b\n" + `out: \q` + "\n"},
		{name: "a spans field that says neither", data: "case: a\nin: b\nspans: maybe\n"},
		{name: "an in field holding the notation", data: "case: a\nin: «p»\n"},
		{name: "a case with nothing in it", data: "case: a\n"},
		{name: "no closing newline", data: "case: a\nin: b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseCorpusFile("example.txt", []byte(tt.data)); err == nil {
				t.Errorf("parseCorpusFile(%q) succeeded, want an error", tt.data)
			}
		})
	}
}

func Test_corpusFile_render(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "a file already generated is left byte for byte",
			data: "# a file\n\ncase: a\nin:   abc\nout:  abc\n",
			want: "# a file\n\ncase: a\nin:   abc\nout:  abc\n",
		},
		{
			name: "an out field is written after the last hand-written line",
			data: "case: a\nin: abc\n",
			want: "case: a\nin:   abc\nout:  abc\n",
		},
		{
			name: "an out field keeps the place it was written in",
			data: "case: a\nout: abc\nin: abc\n",
			want: "case: a\nout:  abc\nin:   abc\n",
		},
		{
			name: "a comment between the fields and the out field stays put",
			data: "case: a\nin: abc\n# nothing here is a credential\nout: abc\n",
			want: "case: a\nin:   abc\n# nothing here is a credential\nout:  abc\n",
		},
		{
			name: "the fields are laid out to one column",
			data: "case:      a\npatterns:  jwt\nin:        abc\n",
			want: "case: a\npatterns: jwt\nin:   abc\nout:  abc\n",
		},
		{
			name: "a field of empty text is written without the column",
			data: "case: a\nin:\n",
			want: "case: a\nin:\nout:\n",
		},
		{
			name: "a directive between cases is laid out too",
			data: "patterns:    jwt\n\ncase: a\nin: abc\n",
			want: "patterns: jwt\n\ncase: a\nin:   abc\nout:  abc\n",
		},
		{
			name: "comments and blank lines are kept",
			data: "# leading\n\n# about the case\ncase: a\nin: abc\n\n# trailing\n",
			want: "# leading\n\n# about the case\ncase: a\nin:   abc\nout:  abc\n\n# trailing\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := parseCorpusFile("example.txt", []byte(tt.data))
			if err != nil {
				t.Fatalf("parseCorpusFile failed: %v", err)
			}
			// The out field a render writes is the one the case carries, which
			// here stands in for what a run would generate.
			for _, c := range f.cases {
				c.out, c.hasOut = c.in, true
			}
			if got := string(f.render()); got != tt.want {
				t.Errorf("render() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_corpusFile_renderRoundTrip(t *testing.T) {
	// Rendering a file that is already generated must leave it byte for byte,
	// which is what lets -update be run at any time and lets a diff mean what it
	// says.
	for _, f := range loadCorpus(t) {
		t.Run(f.name, func(t *testing.T) {
			data, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatalf("reading %s: %v", f.path, err)
			}
			if got := f.render(); !bytes.Equal(got, data) {
				t.Errorf("%s is not what rendering it gives; run go test ./conformance -update", f.path)
			}
		})
	}
}
