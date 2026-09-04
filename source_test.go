// What the source of this package is held to, read from the source itself.
//
// The rules kept here are about how this package is written rather than about
// what it computes, and none of them can be stated as a case: a reference that
// shares a declaration with the scan it checks still agrees with it on every
// input, one written inline at the call is a reference no rule reaches, and a
// doc comment naming the wrong identifier still compiles. They drift in silence
// for exactly that reason, so they are read out of the syntax tree here.

package mask

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode"
)

// sourceFiles parses every Go file of this directory, keyed on the base name.
//
// A directory rather than a package: example_test.go is package mask_test, an
// external test of the same directory, and the rules below differ on whether
// they reach it. What a doc comment opens with is a rule about the source in
// front of a reader and holds there too; what a reference reaches is a rule
// about this package's own declarations, and a name in mask_test is a different
// name that happens to be spelled the same.
//
// The package is parsed rather than reflected over because what these rules are
// about — which declaration an expression reads, what a comment says — is in the
// syntax and not in the values a build produces.
func sourceFiles(t testing.TB) (*token.FileSet, map[string]*ast.File) {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}

	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files[name] = f
	}
	if len(files) == 0 {
		t.Fatal("no Go file was parsed; the test was run from somewhere other than the package directory")
	}
	return fset, files
}

// sortedNames returns the file names in a fixed order, so that a run reports
// what it finds in the same order every time.
func sortedNames(files map[string]*ast.File) []string {
	return slices.Sorted(maps.Keys(files))
}

// spanType is what a reference returns, and the one declaration of the scans it
// may name. sharedWithReferences says why, and takes in the fields with it.
const spanType = "Span"

// checkedPackage type-checks this package and returns what a name resolves to.
//
// Resolving rather than matching names is what makes the rule below exact. A
// name reaches a declaration of the scans in more ways than a walk of the syntax
// can be taught to recognise — as a type, through a field of one, as the
// receiver of a method, as the key of a map literal, as the right-hand side of a
// binding that shadows it — and a walk of the syntax alone has a hole for each
// of those. What a resolver answers instead is the question actually being
// asked: which declaration is this, and which file was it declared in.
//
// The file list comes from go/build, which applies build constraints and so
// returns one consistent set: race_test.go and norace_test.go declare the same
// name, and checking both would fail on a redeclaration no build has. Which of
// the two it leaves out is not the one the running binary left out — build.Default
// carries no race tag — and nothing here reads what they declare, so the rules
// below hold either way.
func checkedPackage(t testing.TB) *checkedSource {
	t.Helper()

	src, err := checkSource()
	if err != nil {
		t.Fatalf("%v", err)
	}
	return src
}

// checkedSource is the package as a resolver answers for it.
type checkedSource struct {
	fset  *token.FileSet
	files []*ast.File
	info  *types.Info
	pkg   *types.Package
}

// checkSource type-checks the package once for the whole run. Every rule below
// reads the same answers, and checking is the longest thing any of them does.
var checkSource = sync.OnceValues(func() (*checkedSource, error) {
	built, err := build.Default.ImportDir(".", 0)
	if err != nil {
		return nil, fmt.Errorf("reading the package directory: %w", err)
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range slices.Concat(built.GoFiles, built.TestGoFiles) {
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		files = append(files, f)
	}

	info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check(built.ImportPath, fset, files, info)
	if err != nil {
		// The importer reads gc export data, which this package needs nothing
		// of: it imports the standard library and no more, and go.mod names no
		// requirement. An import added outside that is where this stops working,
		// and the failure reads as a fault in the source rather than in the
		// reading of it, so it says which it is.
		return nil, fmt.Errorf("type-checking the package: %w\n\tthe rules in source_test.go resolve names with go/types and import with "+
			"go/importer, which reads compiled export data; an import outside the standard library is what this cannot follow", err)
	}
	return &checkedSource{fset: fset, files: files, info: info, pkg: pkg}, nil
})

// sharedWithReferences returns the declarations of the scans a reference may
// name: Span, and the fields a reference fills one in by.
//
// A reference returns Span because that is what the scan returns and what the
// two are compared as, so sharing it is what makes a comparison possible rather
// than what makes the two agree — and a Span it cannot write the fields of is a
// Span it cannot return. Every other declaration is a rule.
func sharedWithReferences(pkg *types.Package) map[types.Object]bool {
	shared := map[types.Object]bool{}
	obj := pkg.Scope().Lookup(spanType)
	if obj == nil {
		return shared
	}
	shared[obj] = true
	if st, ok := obj.Type().Underlying().(*types.Struct); ok {
		for field := range st.Fields() {
			shared[field] = true
		}
	}
	return shared
}

// declaredInTest reports whether obj was declared in a test file.
func declaredInTest(fset *token.FileSet, obj types.Object) bool {
	return strings.HasSuffix(fset.Position(obj.Pos()).Filename, "_test.go")
}

func Test_references_shareNoDeclarationWithTheScans(t *testing.T) {
	// A reference spells the prefixes, the counts and the character classes its
	// scan reads out again rather than reading the scan's own declarations, so
	// that the two can disagree and the fuzz target beside them report it. A
	// reference reading the declaration instead moves with the scan whatever the
	// scan is changed to, and the target then compares a rule with itself: the
	// one input class it exists to find is the one it can no longer reach.
	//
	// Nothing else reports this. The reference still agrees with the scan on
	// every input, the fuzz target still passes and the corpus still holds,
	// because the two are then wrong together or right together and never apart.
	src := checkedPackage(t)
	fset, info, pkg := src.fset, src.info, src.pkg
	bodies := declarationBodies(fset, src.files)
	shared := sharedWithReferences(pkg)
	checked := map[string]bool{}

	for _, f := range src.files {
		name := filepath.Base(fset.Position(f.Pos()).Filename)
		// References live beside the scans they check, which is what the layout
		// asks for and what keeps the rule off this file: the helpers below are
		// named for what they look for rather than being references themselves.
		if !strings.HasPrefix(name, "builtin_") || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		for _, d := range f.Decls {
			for _, ref := range scanReferences(d) {
				checked[name] = true
				w := walk{fset: fset, info: info, pkg: pkg, bodies: bodies, shared: shared, seen: map[types.Object]bool{}}
				for _, r := range w.reads(ref.node, nil) {
					through := ""
					if len(r.via) > 0 {
						through = ", through " + strings.Join(r.via, " then ")
					}
					t.Errorf("%s: %s reads %s%s, which %s declares for the scan; spell it out here instead, so that the two can disagree",
						fset.Position(r.at.Pos()), ref.name, r.obj.Name(), through,
						filepath.Base(fset.Position(r.obj.Pos()).Filename))
				}
			}
		}
	}

	// Every built-in carries a reference, in the file beside its scan, and a
	// file may carry any number of them: a reference written out by hand is
	// several declarations where one built on an expression is two. What is
	// counted is therefore the files a reference was recognised in and not the
	// references themselves, so that a pattern whose reference this stopped
	// reading is reported. A run recognising nothing reads exactly like a run
	// finding nothing wrong.
	if want := len(builtins); len(checked) < want {
		t.Errorf("reference(s) were read in %d of the built-in test files, want %d, one per built-in; a reference this no longer recognises is one nothing holds",
			len(checked), want)
	}
}

// declarationBodies returns, for every package-level declaration of a test file
// and every method one declares, the node to read when a reference reaches it.
//
// Only those. A local is read where it stands, and a field is read through the
// type that carries it, so neither needs a body of its own.
func declarationBodies(fset *token.FileSet, files []*ast.File) map[token.Pos]ast.Node {
	bodies := map[token.Pos]ast.Node{}
	for _, f := range files {
		if !strings.HasSuffix(fset.Position(f.Pos()).Filename, "_test.go") {
			continue
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				bodies[d.Name.Pos()] = d
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					switch sp := sp.(type) {
					case *ast.ValueSpec:
						for _, id := range sp.Names {
							bodies[id.Pos()] = sp
						}
					case *ast.TypeSpec:
						bodies[sp.Name.Pos()] = sp.Type
					}
				}
			}
		}
	}
	return bodies
}

// read is a declaration of the scans a reference reaches, where it was named,
// and the test declarations it was reached through.
type read struct {
	at  *ast.Ident
	obj types.Object
	via []string
}

// walk reads a reference against what its names resolve to.
type walk struct {
	fset   *token.FileSet
	info   *types.Info
	pkg    *types.Package
	bodies map[token.Pos]ast.Node
	shared map[types.Object]bool
	seen   map[types.Object]bool
}

// reads returns what n reaches of the declarations the scans are built from,
// following the test declarations it reaches through.
func (w walk) reads(n ast.Node, via []string) []read {
	if n == nil {
		return nil
	}
	var found []read
	ast.Inspect(n, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		obj := w.info.Uses[id]
		// A name of another package, a builtin, a label, or the definition
		// itself resolves to nothing of this package's own.
		if obj == nil || obj.Pkg() != w.pkg || w.seen[obj] {
			return true
		}
		if !declaredInTest(w.fset, obj) {
			if !w.shared[obj] {
				found = append(found, read{at: id, obj: obj, via: via})
			}
			return true
		}
		body, ok := w.bodies[obj.Pos()]
		if !ok {
			return true // a local or a field of a test's own
		}
		w.seen[obj] = true
		found = append(found, w.reads(body, append(slices.Clone(via), obj.Name()))...)
		return true
	})
	return found
}

func Test_references_liveBesideTheScansTheyCheck(t *testing.T) {
	// The rule above reads builtin_<name>_test.go and nothing else, which is
	// where the layout puts a reference: beside the scan it checks. One lifted
	// somewhere else — into fuzz_test.go beside the body the targets share, or
	// into builtins_test.go beside the properties — would leave that rule with
	// nothing to hold and report nothing at all, which is the way a guard is
	// lost rather than broken. Where they live is held here for that reason.
	//
	// A file that is not a test at all is worse than unchecked. What a reference
	// may not read is decided by declaredInTest, which reads the file a name was
	// declared in, so a reference moved out of a test file becomes a declaration
	// of the scans itself — and the next reference to name it is reported for
	// reading one.
	_, files := sourceFiles(t)

	for _, name := range sortedNames(files) {
		if strings.HasPrefix(name, "builtin_") && strings.HasSuffix(name, "_test.go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") && !inPackage(files[name]) {
			continue
		}
		for _, d := range files[name].Decls {
			for _, ref := range scanReferences(d) {
				t.Errorf("%s declares %s, which reads as a reference; a reference belongs in the builtin_<name>_test.go of the scan it checks, which is where Test_references_shareNoDeclarationWithTheScans looks for one", name, ref.name)
			}
		}
	}
}

// inPackage reports whether f is part of package mask rather than the external
// test package beside it, whose names are its own.
func inPackage(f *ast.File) bool { return f.Name.Name == "mask" }

func Test_references_areNamedRatherThanWritten(t *testing.T) {
	// Every per-pattern target hands fuzzAgainstReference the reference its scan
	// is compared with, and the two rules above read a reference by its
	// declaration. One written inline at the call, or bound to a local, is a
	// reference no declaration holds: neither rule reaches it, and the target may
	// then be comparing the scan with an expression naming the scan's own
	// declarations — which is the whole of what those rules are for, arrived at by
	// writing no reference at all rather than by sharing one.
	//
	// The argument is resolved rather than read by name. A local named for a
	// declared reference shadows it, carries the name every check here would
	// match, and is a declaration nothing reads.
	const driver = "fuzzAgainstReference"
	const refArg = 2 // f, find, ref

	src := checkedPackage(t)
	found := 0
	for _, f := range src.files {
		if !strings.HasSuffix(src.fset.Position(f.Pos()).Filename, "_test.go") {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != driver || len(call.Args) <= refArg {
				return true
			}
			found++

			arg := call.Args[refArg]
			if ref, ok := arg.(*ast.Ident); ok {
				obj := src.info.Uses[ref]
				if obj != nil && obj.Parent() == src.pkg.Scope() && strings.HasPrefix(obj.Name(), "reference") {
					return true
				}
			}
			t.Errorf("%s: %s is handed a reference that is not a declaration named for one; declare it as reference<Pattern>Find beside the scan, which is where the rules above read one",
				src.fset.Position(arg.Pos()), driver)
			return true
		})
	}

	// A guard reading nothing reads clean. Rename the driver, or route the
	// targets through a wrapper, and every walk above matches no call at all and
	// this passes on having checked none of them — which is how the other rules
	// here are lost too, and why each of them counts what it found.
	if want := len(builtins); found != want {
		t.Errorf("%d call(s) to %s were found, want %d, one per built-in; the rule above reads them by that name and checks nothing if it changes",
			found, driver, want)
	}
}

// scanReference is a declaration holding a reference implementation, under the
// name a failure reports it by. The node is the declaration whole — signature,
// receiver and body alike — since a reference is written against all of it.
type scanReference struct {
	name string
	node ast.Node
}

// scanReferences returns the reference implementations a declaration holds.
//
// The name is what marks one. A reference is written beside the scan it checks
// and named for it, which is the convention every builtin_<name>_test.go
// already keeps, so nothing has to be listed here for a new one to be held to
// the rule above.
func scanReferences(d ast.Decl) []scanReference {
	var found []scanReference
	switch d := d.(type) {
	case *ast.FuncDecl:
		if d.Recv == nil && strings.HasPrefix(d.Name.Name, "reference") {
			found = append(found, scanReference{name: d.Name.Name, node: d})
		}
	case *ast.GenDecl:
		if d.Tok != token.VAR && d.Tok != token.CONST {
			return nil
		}
		for _, s := range d.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, id := range vs.Names {
				if !strings.HasPrefix(id.Name, "reference") {
					continue
				}
				found = append(found, scanReference{name: id.Name, node: vs})
			}
		}
	}
	return found
}

func Test_builtinTests_declareNoMatchAndInContext(t *testing.T) {
	// Every builtin_<name>_test.go keeps a test named _noMatch, stating what the
	// pattern leaves alone, and a test named _inContext, stating what Mask does
	// to a value standing in the kind of text it is written into. Those are the
	// two chosen to hold here: a word-boundary test is carried too, but under
	// different spellings across the files that have one, so it names no rule
	// this can state without forcing files into a shape they do not share.
	//
	// Nothing else catches a file missing either slot: go test collects whatever
	// a file declares and reports nothing for what it does not, so an empty slot
	// compiles, runs and passes clean. This is read out of the syntax tree of
	// builtin_*_test.go itself, so it holds without reading builtins.go or
	// builtinPatterns and does not move when either grows.
	_, files := sourceFiles(t)

	for _, name := range sortedNames(files) {
		if !strings.HasPrefix(name, "builtin_") || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		var hasNoMatch, hasInContext bool
		for _, d := range files[name].Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test_") {
				continue
			}
			hasNoMatch = hasNoMatch || strings.HasSuffix(fn.Name.Name, "_noMatch")
			hasInContext = hasInContext || strings.HasSuffix(fn.Name.Name, "_inContext")
		}
		if !hasNoMatch {
			t.Errorf("%s declares no Test_<Pattern>_noMatch, stating what the pattern leaves alone", name)
		}
		if !hasInContext {
			t.Errorf("%s declares no Test_<Pattern>_inContext, stating what Mask does to a value in context", name)
		}
	}
}

func Test_docComments_nameWhatTheyDocument(t *testing.T) {
	// A doc comment opens with the name of what it documents, so that reading
	// one tells you what you are reading about. A comment naming something else
	// is a comment that was moved, or a declaration renamed under it, and the
	// reader is then sent looking for an identifier that is not there — or
	// renames the declaration to match, which for a fuzz target parts it from
	// the corpus in testdata/fuzz keyed on its name.
	//
	// staticcheck's ST1020 states this rule and reaches only exported
	// declarations outside _test.go, which leaves out every fuzz target, every
	// reference and every helper the tests here are built from — where the names
	// are longest and a rename is most likely to leave a comment behind.
	fset, files := sourceFiles(t)

	for _, name := range sortedNames(files) {
		for _, d := range files[name].Decls {
			documented, doc := documentedName(d)
			if documented == "" || doc == nil {
				continue
			}
			text := strings.TrimSpace(doc.Text())
			// A comment opening on the deprecation marker is following the
			// convention that puts it first, and names what it documents behind
			// it or not at all.
			if text == "" || strings.HasPrefix(text, "Deprecated:") {
				continue
			}
			first := openingWord(text)
			if first == documented {
				continue
			}
			t.Errorf("%s: the doc comment on %s opens with %q", fset.Position(d.Pos()), documented, first)
		}
	}
}

// openingWord returns the word a comment opens on, as a name would be written.
//
// The word ends at the first space of any kind, which a comment writing the name
// on a line of its own reaches at a newline rather than at a blank. What closes
// a clause is taken off the end, and so is a parameter list: a comment opening
// Fill(r) names Fill, and reading it as a different word would report a comment
// that names exactly what it documents.
func openingWord(text string) string {
	first := text
	if i := strings.IndexFunc(first, func(r rune) bool { return unicode.IsSpace(r) || r == '(' }); i >= 0 {
		first = first[:i]
	}
	return strings.TrimRight(first, ".,:;")
}

// documentedName returns what a function declares and the comment above it.
//
// Functions alone. The comment above a built-in's pattern variable is the
// rationale for the scan under it — what it anchors on, where it resumes from,
// what holds it linear — and opens on that rather than on the variable, which
// is a name the reader has no reason to be told twice. Holding those to this
// rule would be asking that prose to open with a word it has no use for.
func documentedName(d ast.Decl) (string, *ast.CommentGroup) {
	f, ok := d.(*ast.FuncDecl)
	if !ok {
		return "", nil
	}
	return f.Name.Name, f.Doc
}
