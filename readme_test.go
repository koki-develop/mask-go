// What README.md claims about the registry, held against the registry.
//
// A count kept in prose is what this repository otherwise refuses, and
// README.md keeps three: a reader deciding whether to depend on the library
// reads them before anything else. So they are held here rather than trusted.
//
// The table beside them is held against the syntax tree rather than a list
// written out here: a row a vendor and a row a pattern belonging to none, which
// is the shape vendors.go already argues for.

package mask

import (
	"go/ast"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// readmeSentence is the claim above the table: the count of built-in patterns,
// of vendors, and of the kinds of credential the table names between them.
var readmeSentence = regexp.MustCompile(
	`The (\d+) built-in patterns cover (\d+) vendors and locate (\d+) kinds of credential:`,
)

// readmeRow is a row of that table: an accessor, the signature it is written
// with, and the kinds it locates written as a comma-separated list.
var readmeRow = regexp.MustCompile("^\\| `([A-Za-z0-9]+)\\(\\) (\\[\\]Pattern|Pattern)` \\| (.+) \\|$")

// readmeAccessorRow is one row of the table as this file reads it.
type readmeAccessorRow struct {
	accessor  string
	signature string
	locates   string // the row's Locates cell, verbatim
	kinds     int
}

// readREADME returns the three counts the sentence states and the rows of the
// table under it.
func readREADME(t *testing.T) (patterns, vendors, kinds int, rows []readmeAccessorRow) {
	t.Helper()

	b, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	src := string(b)

	m := readmeSentence.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("README.md states no count of the built-in patterns; %v is what this reads", readmeSentence)
	}
	counts := make([]int, 3)
	for i := range counts {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			t.Fatalf("reading the count %q the sentence states: %v", m[i+1], err)
		}
		counts[i] = n
	}

	for line := range strings.SplitSeq(src, "\n") {
		r := readmeRow.FindStringSubmatch(line)
		if r == nil {
			continue
		}
		rows = append(rows, readmeAccessorRow{
			accessor:  r[1],
			signature: r[2],
			locates:   r[3],
			// The kinds are written as one comma-separated list a row, so
			// what a row states is one more than the commas in it.
			kinds: strings.Count(r[3], ",") + 1,
		})
	}
	if len(rows) == 0 {
		t.Fatal("README.md holds no accessor table, so nothing below is being checked")
	}
	return counts[0], counts[1], counts[2], rows
}

// declaredAccessors returns, from the syntax tree, every accessor returning one
// pattern keyed on its own name, with the pattern it returns, and every pattern
// named in an accessor of vendors.go.
//
// Keyed on the accessor rather than on the pattern, because two accessors may
// return one pattern: keyed the other way round they would collapse to
// whichever the walk reached last, which is the order a map is ranged over, and
// the survivor would be the only one this file asked README.md for a row for.
//
// Both are read rather than listed so that an accessor added to a
// builtin_<name>.go, or a pattern joining a vendor, reaches this file without
// anything here being edited.
func declaredAccessors(t *testing.T) (single map[string]string, withVendor map[string]bool) {
	t.Helper()

	_, files := sourceFiles(t)
	single, withVendor = map[string]string{}, map[string]bool{}

	for name, f := range files {
		// The accessors README names are the exported surface, which is
		// declared outside the tests. A helper written in a _test.go file with
		// the shape of an accessor would otherwise be read as one, and one
		// returning a pattern an accessor already returns would take that
		// pattern's name over.
		if !inPackage(f) || strings.HasSuffix(name, "_test.go") {
			continue
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil || fn.Type.Results == nil {
				continue
			}
			if len(fn.Type.Results.List) != 1 || len(fn.Body.List) != 1 {
				continue
			}
			ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				continue
			}

			switch res := fn.Type.Results.List[0].Type.(type) {
			case *ast.Ident:
				// func X() Pattern { return v }
				if res.Name != "Pattern" {
					continue
				}
				if id, ok := ret.Results[0].(*ast.Ident); ok {
					single[fn.Name.Name] = id.Name
				}
			case *ast.ArrayType:
				// func <Vendor>Patterns() []Pattern { return []Pattern{…} }
				id, ok := res.Elt.(*ast.Ident)
				if !ok || id.Name != "Pattern" || name != "vendors.go" {
					continue
				}
				lit, ok := ret.Results[0].(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, e := range lit.Elts {
					if id, ok := e.(*ast.Ident); ok {
						withVendor[id.Name] = true
					}
				}
			}
		}
	}
	if len(single) == 0 || len(withVendor) == 0 {
		t.Fatal("no accessor was read out of the syntax tree, so nothing below is being checked")
	}
	return single, withVendor
}

func Test_README_countsWhatItClaims(t *testing.T) {
	patterns, vendors, kinds, rows := readREADME(t)

	if got := len(AllBuiltinPatterns()); patterns != got {
		t.Errorf("README.md counts %d built-in patterns and the registry holds %d", patterns, got)
	}
	if got := len(vendorAccessors); vendors != got {
		t.Errorf("README.md counts %d vendors and vendors.go declares %d accessors", vendors, got)
	}

	// The kinds are counted off the table rather than off anything the package
	// declares, because no declaration carries them: what a vendor calls the
	// credentials behind one prefix is prose, and the table is where it is
	// written. So this holds the sentence to the table under it, which is the
	// half that can be counted, and leaves the table itself to a reader.
	total := 0
	for _, r := range rows {
		total += r.kinds
	}
	if kinds != total {
		t.Errorf("README.md counts %d kinds of credential and its table names %d", kinds, total)
	}
}

func Test_README_namesEveryAccessor(t *testing.T) {
	_, _, _, rows := readREADME(t)
	single, withVendor := declaredAccessors(t)

	// A row a vendor accessor, and a row for each pattern belonging to none.
	// The second set is derived rather than read from patternsWithNoVendor:
	// that table names the patterns and this needs the accessors, and deriving
	// keeps a pattern that quietly left every vendor from being covered here by
	// the very list that stopped naming it.
	want := map[string]string{}
	for name := range vendorAccessors {
		want[name] = "[]Pattern"
	}
	noVendor := map[string]bool{}
	for accessor, pattern := range single {
		if withVendor[pattern] {
			continue
		}
		want[accessor] = "Pattern"
		noVendor[pattern] = true
	}
	if len(noVendor) != len(patternsWithNoVendor) {
		t.Errorf("%d built-in pattern(s) belong to no vendor accessor and patternsWithNoVendor names %d",
			len(noVendor), len(patternsWithNoVendor))
	}

	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.accessor] {
			t.Errorf("README.md gives %s a row twice", r.accessor)
		}
		seen[r.accessor] = true

		signature, ok := want[r.accessor]
		if !ok {
			t.Errorf("README.md gives %s a row and this package declares no such accessor", r.accessor)
			continue
		}
		if r.signature != signature {
			t.Errorf("README.md writes %s as returning %s, where it returns %s",
				r.accessor, r.signature, signature)
		}
	}

	missing := make([]string, 0, len(want))
	for name := range want {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	slices.Sort(missing)
	for _, name := range missing {
		t.Errorf("%s is declared and README.md gives it no row", name)
	}
}

// Test_README_everyKindIsNamed holds readmeRow's Locates cell to naming
// something: the regexp's `(.+)` matches a single space, so a blank cell would
// otherwise be counted as one kind and Test_README_countsWhatItClaims would
// hold the sentence's count against a table that says nothing for that row.
func Test_README_everyKindIsNamed(t *testing.T) {
	_, _, _, rows := readREADME(t)

	for _, r := range rows {
		for raw := range strings.SplitSeq(r.locates, ", ") {
			if strings.TrimSpace(raw) == "" {
				t.Errorf("%s names %q as a kind of credential it locates, which is an empty cell rather than a kind", r.accessor, raw)
			}
		}
	}
}

// Test_README_tableIsOrdered holds the accessor table to the order a reader
// scans it in: case-insensitively by accessor name, which is the order a row
// added by the add-pattern workflow is expected to land in and the order a
// row inserted anywhere else would disagree with.
func Test_README_tableIsOrdered(t *testing.T) {
	_, _, _, rows := readREADME(t)

	names := make([]string, len(rows))
	for i, r := range rows {
		names[i] = r.accessor
	}
	if !slices.IsSortedFunc(names, func(a, b string) int {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	}) {
		t.Error("README.md's accessor table is not sorted case-insensitively by accessor name")
	}
}

// requireViolations returns every module go.mod's content requires, read out
// of a "require <module> <version>" line or a "require (...)" block — go.mod
// may hold any number of either, `go mod tidy` routinely writing a direct
// block and an indirect block side by side, so every match of each form is
// read rather than the first. A blank line or a "//" comment inside a block
// names no module and reports nothing. Its caller checks the result against
// README.md's "zero dependencies" claim, so the name is the caller's: any
// module this returns is already a violation of that claim, one dependency
// being one too many.
func requireViolations(mod string) []string {
	var mods []string

	// [ \t]+ rather than \s+ on both sides: \s admits a newline, so on a block
	// whose first module path happens to begin with v — "require (\nv2.x
	// v1.0\n)" — \s+ would read across the line break and this would report
	// the block's own "(" as a module name. Confining both gaps to the line
	// "require (" opens on leaves nothing after "(" to be a v-prefixed
	// module, so only a real "require <module> v..." line matches; the block
	// form below reads such a block correctly already.
	requireLine := regexp.MustCompile(`(?m)^require[ \t]+(\S+)[ \t]+v`)
	for _, m := range requireLine.FindAllStringSubmatch(mod, -1) {
		mods = append(mods, m[1])
	}

	inBlock := regexp.MustCompile(`(?ms)^require \(\n(.*?)^\)`)
	for _, m := range inBlock.FindAllStringSubmatch(mod, -1) {
		for line := range strings.SplitSeq(strings.TrimSpace(m[1]), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			mods = append(mods, strings.Fields(line)[0])
		}
	}

	return mods
}

// Test_requireViolations drives requireViolations directly, off go.mod
// content built literally in each case rather than the module's own go.mod,
// so every shape a go.mod may hold a require directive in is covered: a lone
// "require" line, a single block, a block holding a blank line or a
// "// indirect" comment, and two blocks side by side — the shape `go mod
// tidy` writes for a direct and an indirect block together.
func Test_requireViolations(t *testing.T) {
	tests := []struct {
		name string
		mod  string
		want []string
	}{
		{
			name: "no require directive",
			mod:  "module example.com/x\n\ngo 1.23\n",
			want: nil,
		},
		{
			name: "lone require line",
			mod:  "module example.com/x\n\ngo 1.23\n\nrequire example.com/one v1.2.3\n",
			want: []string{"example.com/one"},
		},
		{
			name: "single block",
			mod:  "module example.com/x\n\ngo 1.23\n\nrequire (\n\texample.com/one v1.2.3\n\texample.com/two v4.5.6\n)\n",
			want: []string{"example.com/one", "example.com/two"},
		},
		{
			name: "block with a blank line and an indirect comment",
			mod:  "module example.com/x\n\ngo 1.23\n\nrequire (\n\texample.com/one v1.2.3\n\n\texample.com/two v4.5.6 // indirect\n)\n",
			want: []string{"example.com/one", "example.com/two"},
		},
		{
			name: "two blocks side by side",
			mod: "module example.com/x\n\ngo 1.23\n\nrequire (\n\texample.com/one v1.2.3\n)\n\n" +
				"require (\n\texample.com/two v4.5.6 // indirect\n)\n",
			want: []string{"example.com/one", "example.com/two"},
		},
		{
			name: "block whose first module path begins with v",
			mod:  "module example.com/x\n\ngo 1.23\n\nrequire (\n\tv2.example.com/one v1.2.3\n)\n",
			want: []string{"v2.example.com/one"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requireViolations(tt.mod); !slices.Equal(got, tt.want) {
				t.Errorf("requireViolations(%q) = %v, want %v", tt.mod, got, tt.want)
			}
		})
	}
}

// Test_README_zeroDependencies holds README.md's "with zero dependencies" to
// go.mod: a require directive naming a module other than the standard library
// would make the claim false while nothing else here reads go.mod at all.
func Test_README_zeroDependencies(t *testing.T) {
	b, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	if !strings.Contains(string(b), "zero dependencies") {
		t.Fatal(`README.md states no "zero dependencies" claim, so nothing below is being checked`)
	}

	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	for _, name := range requireViolations(string(mod)) {
		t.Errorf("go.mod requires %s; README.md's \"zero dependencies\" is no longer true", name)
	}
}

// Test_README_installsTheModulePath holds README.md's "go get" line to
// go.mod's own module path, so the two name the same module rather than
// agreeing only by having been written down together once.
func Test_README_installsTheModulePath(t *testing.T) {
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	m := regexp.MustCompile(`(?m)^module (\S+)`).FindStringSubmatch(string(mod))
	if m == nil {
		t.Fatal("go.mod states no module path")
	}
	path := m[1]

	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}
	if want := "go get " + path; !strings.Contains(string(readme), want) {
		t.Errorf("README.md does not contain %q, go.mod's own module path", want)
	}
}

// Test_registry_everyPatternHasItsOwnExportedAccessor holds every built-in to
// having an accessor of its own — a func returning it alone as a Pattern, the
// third face .claude/rules/builtin-patterns.md names beside WithPatterns and
// Match.Pattern — rather than being reachable only through AllBuiltinPatterns
// and its vendor accessor. declaredAccessors reads every such accessor out of
// the syntax tree, so a pattern added to builtins and to a vendor accessor
// without one of its own moves the two counts apart.
func Test_registry_everyPatternHasItsOwnExportedAccessor(t *testing.T) {
	single, _ := declaredAccessors(t)

	if got, want := len(single), len(builtins); got != want {
		t.Errorf("%d single-pattern accessor(s) are declared and the registry holds %d pattern(s); a pattern reachable only through AllBuiltinPatterns and its vendor accessor is missing one of its own", got, want)
	}
}

// readmeGoBlock is one ```go fenced code block of README.md: its code lines,
// verbatim, and the text of a trailing "// <output>" comment where the block
// ends with one.
type readmeGoBlock struct {
	lines  []string
	output string
}

var readmeGoFence = regexp.MustCompile("(?s)```go\n(.*?)\n```")

// readmeGoBlocks returns every ```go fenced block of README.md.
func readmeGoBlocks(t *testing.T) []readmeGoBlock {
	t.Helper()

	b, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}

	var blocks []readmeGoBlock
	for _, m := range readmeGoFence.FindAllStringSubmatch(string(b), -1) {
		lines := strings.Split(m[1], "\n")
		blk := readmeGoBlock{lines: lines}
		if last := lines[len(lines)-1]; strings.HasPrefix(last, "// ") {
			blk.output = strings.TrimPrefix(last, "// ")
			blk.lines = lines[:len(lines)-1]
		}
		blocks = append(blocks, blk)
	}
	if len(blocks) == 0 {
		t.Fatal("README.md holds no ```go fenced block, so nothing below is being checked")
	}
	return blocks
}

// nonBlankLines splits s into lines, trims each, and drops the ones left
// empty — which is what lets a block's code be compared to example_test.go
// modulo the tabs a function body is indented with and the blank lines either
// side chooses to separate statements with.
func nonBlankLines(s string) []string {
	var out []string
	for line := range strings.SplitSeq(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// containsLineRun reports whether needle appears as a contiguous run of
// haystack, in order.
func containsLineRun(haystack, needle []string) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if slices.Equal(haystack[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

// readmeFenceIsIllustrative reports whether code stands for a value or a
// process-wide effect no self-contained Example can reproduce: an
// *http.Response this package never receives, or the process's default
// logger, which no other Example may touch without one running changing what
// another observes. Those two are read by a person rather than held here.
func readmeFenceIsIllustrative(code string) bool {
	return strings.Contains(code, "resp.Body") || strings.Contains(code, "log.SetOutput")
}

// Test_README_goBlocksAreExamples holds every runnable ```go block of
// README.md to appearing, modulo blank lines and indentation, inside
// example_test.go — and a block ending with a "// <output>" comment to that
// same text carrying an Example whose declared Output is that comment. Absent
// this, README's prose and example_test.go's Examples are two texts an editor
// can bring out of step with each other and nothing reports it.
func Test_README_goBlocksAreExamples(t *testing.T) {
	exampleSrc, err := os.ReadFile("example_test.go")
	if err != nil {
		t.Fatalf("reading example_test.go: %v", err)
	}
	haystack := nonBlankLines(string(exampleSrc))

	checked := 0
	for _, blk := range readmeGoBlocks(t) {
		code := strings.Join(blk.lines, "\n")
		if readmeFenceIsIllustrative(code) {
			continue
		}
		checked++

		needle := nonBlankLines(code)
		if !containsLineRun(haystack, needle) {
			t.Errorf("README.md's block:\n%s\ndoes not appear in example_test.go, modulo blank lines and indentation", code)
			continue
		}
		if blk.output == "" {
			continue
		}
		want := "// Output: " + blk.output
		if !strings.Contains(string(exampleSrc), want) {
			t.Errorf("README.md's block ends with %q and no Example in example_test.go declares %q", "// "+blk.output, want)
		}
	}
	if checked == 0 {
		t.Fatal("every ```go block in README.md was read as illustrative, so nothing was checked")
	}
}

// Test_packageDoc_sampleIsExample holds the package doc comment's own runnable
// sample and its "Output:" block to example_test.go, the same way
// Test_README_goBlocksAreExamples holds README.md's blocks to it: doc.Text
// keeps a code line indented by a tab and leaves prose unindented, which is
// how the two are told apart here.
func Test_packageDoc_sampleIsExample(t *testing.T) {
	_, files := sourceFiles(t)
	f, ok := files["mask.go"]
	if !ok || f.Doc == nil {
		t.Fatal("mask.go carries no package doc comment; the package doc's runnable sample is somewhere this test does not read")
	}
	doc := f.Doc.Text()

	const marker = "\nOutput:\n\n"
	before, after, ok := strings.Cut(doc, marker)
	if !ok {
		t.Fatal(`the package doc states no "Output:" block, so nothing below is being checked`)
	}

	var code []string
	for line := range strings.SplitSeq(before, "\n") {
		if tail, ok := strings.CutPrefix(line, "\t"); ok {
			code = append(code, tail)
		}
	}
	if len(code) == 0 {
		t.Fatal("the package doc's sample carries no indented code line")
	}

	outputLine, _, _ := strings.Cut(after, "\n")
	output, ok := strings.CutPrefix(outputLine, "\t")
	if !ok || output == "" {
		t.Fatal(`the package doc's "Output:" block carries no indented line`)
	}

	exampleSrc, err := os.ReadFile("example_test.go")
	if err != nil {
		t.Fatalf("reading example_test.go: %v", err)
	}
	src := string(exampleSrc)

	if !containsLineRun(nonBlankLines(src), nonBlankLines(strings.Join(code, "\n"))) {
		t.Errorf("the package doc's sample:\n%s\ndoes not appear in example_test.go, modulo blank lines and indentation", strings.Join(code, "\n"))
	}
	if want := "// Output: " + output; !strings.Contains(src, want) {
		t.Errorf("the package doc states the output %q and no Example in example_test.go declares %q", output, want)
	}
}
