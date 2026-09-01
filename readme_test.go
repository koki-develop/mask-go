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
