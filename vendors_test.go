// What the vendor accessors are held to.
//
// An accessor is a slice literal, so what can go wrong with one is not that it
// computes the wrong thing but that it and the registry stopped agreeing: a
// pattern added to builtins and to no accessor is reachable only through
// AllBuiltinPatterns, a pattern returned by two accessors says it belongs to
// two vendors, and an accessor declared in vendors.go that no test names is
// held to nothing at all. None of the three fails to compile and none of them
// changes what Mask returns, which is why they are read here.

package mask

import (
	"go/ast"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
)

// vendorAccessors is every accessor of vendors.go, keyed on the name it is
// declared under.
//
// The key is written out rather than derived so that a failure names the
// accessor a reader can go and open. That the table and the file name the same
// accessors is held by Test_vendorAccessors_nameEveryAccessorDeclared, which
// reads the declarations out of the syntax tree — without it an accessor added
// to vendors.go but not to this table would be covered by nothing, and the
// coverage below would still pass wherever the pattern it returns is returned
// by some other accessor too.
var vendorAccessors = map[string]func() []Pattern{
	"AgePatterns":          AgePatterns,
	"AirtablePatterns":     AirtablePatterns,
	"AnthropicPatterns":    AnthropicPatterns,
	"AWSPatterns":          AWSPatterns,
	"BuildkitePatterns":    BuildkitePatterns,
	"CircleCIPatterns":     CircleCIPatterns,
	"CloudflarePatterns":   CloudflarePatterns,
	"CratesIOPatterns":     CratesIOPatterns,
	"DatabricksPatterns":   DatabricksPatterns,
	"DigitalOceanPatterns": DigitalOceanPatterns,
	"DockerPatterns":       DockerPatterns,
	"DopplerPatterns":      DopplerPatterns,
	"DynatracePatterns":    DynatracePatterns,
	"FlyIOPatterns":        FlyIOPatterns,
	"GitHubPatterns":       GitHubPatterns,
	"GitLabPatterns":       GitLabPatterns,
	"GooglePatterns":       GooglePatterns,
	"GrafanaPatterns":      GrafanaPatterns,
	"GroqPatterns":         GroqPatterns,
	"HashiCorpPatterns":    HashiCorpPatterns,
	"HerokuPatterns":       HerokuPatterns,
	"HuggingFacePatterns":  HuggingFacePatterns,
	"LangSmithPatterns":    LangSmithPatterns,
	"LinearPatterns":       LinearPatterns,
	"MailchimpPatterns":    MailchimpPatterns,
	"MailerSendPatterns":   MailerSendPatterns,
	"NeonPatterns":         NeonPatterns,
	"NetlifyPatterns":      NetlifyPatterns,
	"NewRelicPatterns":     NewRelicPatterns,
	"NotionPatterns":       NotionPatterns,
	"NPMPatterns":          NPMPatterns,
	"OnePasswordPatterns":  OnePasswordPatterns,
	"OpenAIPatterns":       OpenAIPatterns,
	"OpenRouterPatterns":   OpenRouterPatterns,
	"OryPatterns":          OryPatterns,
	"PaddlePatterns":       PaddlePatterns,
	"PerplexityPatterns":   PerplexityPatterns,
	"PineconePatterns":     PineconePatterns,
	"PlanetScalePatterns":  PlanetScalePatterns,
	"PostHogPatterns":      PostHogPatterns,
	"PostmanPatterns":      PostmanPatterns,
	"PulumiPatterns":       PulumiPatterns,
	"PyPIPatterns":         PyPIPatterns,
	"RenderPatterns":       RenderPatterns,
	"ReplicatePatterns":    ReplicatePatterns,
	"ResendPatterns":       ResendPatterns,
	"RubyGemsPatterns":     RubyGemsPatterns,
	"SendGridPatterns":     SendGridPatterns,
	"SentryPatterns":       SentryPatterns,
	"ShippoPatterns":       ShippoPatterns,
	"ShopifyPatterns":      ShopifyPatterns,
	"SlackPatterns":        SlackPatterns,
	"SonarQubePatterns":    SonarQubePatterns,
	"SourcegraphPatterns":  SourcegraphPatterns,
	"StripePatterns":       StripePatterns,
	"SupabasePatterns":     SupabasePatterns,
	"TailscalePatterns":    TailscalePatterns,
	"XAIPatterns":          XAIPatterns,
}

// patternsWithNoVendor is every built-in that names a format rather than a
// credential some vendor issues, and so belongs to no accessor.
//
// It is a declaration rather than an absence so that the coverage below can
// tell a pattern deliberately left out of the accessors from one forgotten.
// Adding to it is how a pattern says it has no vendor, which is a line a
// reviewer reads; leaving a pattern out of both is what fails.
var patternsWithNoVendor = []Pattern{jsonWebToken, privateKey}

func Test_vendorAccessors_nameEveryAccessorDeclared(t *testing.T) {
	_, files := sourceFiles(t)
	f, ok := files["vendors.go"]
	if !ok {
		t.Fatal("vendors.go was not parsed; the accessors are somewhere this test does not read")
	}

	declared := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !fn.Name.IsExported() {
			continue
		}
		declared[fn.Name.Name] = true
	}

	for _, name := range slices.Sorted(maps.Keys(declared)) {
		if _, ok := vendorAccessors[name]; !ok {
			t.Errorf("vendors.go declares %s, which vendorAccessors does not name", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(vendorAccessors)) {
		if !declared[name] {
			t.Errorf("vendorAccessors names %s, which vendors.go does not declare", name)
		}
	}
}

func Test_vendorAccessors_coverEveryBuiltin(t *testing.T) {
	// Every built-in belongs to exactly one accessor or is named as having no
	// vendor. A pattern in neither is reachable only through
	// AllBuiltinPatterns, which is the hole a caller reaching for a vendor
	// falls into and which nothing else here would report.
	from := make(map[Pattern]string, len(builtins))
	for _, name := range slices.Sorted(maps.Keys(vendorAccessors)) {
		patterns := vendorAccessors[name]()
		if len(patterns) == 0 {
			t.Errorf("%s returns no pattern at all", name)
		}
		for _, p := range patterns {
			if before, ok := from[p]; ok {
				t.Errorf("%s and %s both return %q, so it belongs to two vendors", before, name, p.Name())
				continue
			}
			if !slices.Contains(builtins, p) {
				t.Errorf("%s returns %q, which is not in builtins", name, p.Name())
				continue
			}
			from[p] = name
		}
	}

	for _, p := range patternsWithNoVendor {
		if before, ok := from[p]; ok {
			t.Errorf("%q is returned by %s and is also named in patternsWithNoVendor", p.Name(), before)
			continue
		}
		if !slices.Contains(builtins, p) {
			t.Errorf("patternsWithNoVendor names %q, which is not in builtins", p.Name())
			continue
		}
		from[p] = "patternsWithNoVendor"
	}

	for _, p := range builtins {
		if _, ok := from[p]; !ok {
			t.Errorf("%q is in no vendor accessor and is not named in patternsWithNoVendor", p.Name())
		}
	}
}

func Test_vendorAccessors_freshEachCall(t *testing.T) {
	// A caller may sort what it is handed or append to it, and neither may
	// reach the next caller. An accessor returning a slice it keeps would hand
	// the same array out twice.
	for _, name := range slices.Sorted(maps.Keys(vendorAccessors)) {
		t.Run(name, func(t *testing.T) {
			accessor := vendorAccessors[name]
			first := accessor()
			if len(first) == 0 {
				t.Fatal("the accessor returns no pattern at all")
			}
			first[0] = fixed("replaced")
			if second := accessor(); second[0] == first[0] {
				t.Error("modifying the returned slice changed what a later call returns")
			}
		})
	}
}

func Test_vendorAccessors_returnUsablePatterns(t *testing.T) {
	// The properties every built-in is held to are driven from builtinPatterns,
	// which reads the registry. What is left to hold here is that an accessor
	// hands out the pattern rather than a nil the caller would pass to
	// WithPatterns and lose a Mask call to.
	for _, name := range slices.Sorted(maps.Keys(vendorAccessors)) {
		t.Run(name, func(t *testing.T) {
			for i, p := range vendorAccessors[name]() {
				if p == nil {
					t.Errorf("the pattern at %d is nil", i)
					continue
				}
				if p.Name() == "" {
					t.Errorf("the pattern at %d reports no name", i)
				}
			}
		})
	}
}

// Test_vendorAccessors_appendDoesNotClobberAnotherCall holds "freshly
// allocated" to the use it is written for: a caller appending to what an
// accessor returned. Test_vendorAccessors_freshEachCall already holds element
// 0 of a re-called accessor to being untouched by a write to an earlier call's
// slice; what it does not reach is a slice returned with spare capacity, since
// overwriting element 0 never lands there. An append does, and two callers
// appending to their own calls — the exact shape append(mask.XPatterns(), y)
// and slices.Concat put a caller in — must not let one caller's element
// overwrite the other's.
func Test_vendorAccessors_appendDoesNotClobberAnotherCall(t *testing.T) {
	for _, name := range slices.Sorted(maps.Keys(vendorAccessors)) {
		t.Run(name, func(t *testing.T) {
			accessor := vendorAccessors[name]

			first := accessor()
			if cap(first) != len(first) {
				t.Fatalf("cap is %d and len is %d; an append would write into space this call still owns rather than allocating", cap(first), len(first))
			}

			wantA, wantB := fixed("a"), fixed("b")
			a := append(accessor(), wantA)
			b := append(accessor(), wantB)
			if a[len(a)-1] != wantA {
				t.Error("a second caller's append changed what the first caller's append holds")
			}
			if b[len(b)-1] != wantB {
				t.Error("a second caller's append does not hold what it appended")
			}

			if fresh := accessor(); len(fresh) != len(first) {
				t.Errorf("after two callers appended, a fresh call reports %d pattern(s) where the accessor itself holds %d", len(fresh), len(first))
			}
		})
	}
}

// Test_vendorAccessors_mutatingOneLeavesTheRestIntact holds the other half of
// "freshly allocated": a caller who overwrites what one accessor returned, or
// reverses it in place, must reach neither AllBuiltinPatterns nor any other
// accessor. Nothing before this crosses from one accessor's return to
// another's, or to AllBuiltinPatterns.
func Test_vendorAccessors_mutatingOneLeavesTheRestIntact(t *testing.T) {
	before := slices.Clone(AllBuiltinPatterns())
	mutated := fixed("mutated")

	for _, name := range slices.Sorted(maps.Keys(vendorAccessors)) {
		p := vendorAccessors[name]()
		for i := range p {
			p[i] = mutated
		}
		slices.Reverse(p)
	}

	if !slices.Equal(AllBuiltinPatterns(), before) {
		t.Error("mutating what the accessors returned changed what AllBuiltinPatterns reports")
	}
	for _, name := range slices.Sorted(maps.Keys(vendorAccessors)) {
		for i, p := range vendorAccessors[name]() {
			if p == mutated {
				t.Errorf("%s still reports the mutation made to an earlier call, at index %d", name, i)
			}
		}
	}
}

// Test_vendorAccessors_reportTheSameOrderEachCall holds an accessor to
// reporting its patterns in the same order every time. Masker.Mask attributes
// a value two patterns both locate to whichever was added first by
// WithPatterns, so an accessor whose order varied from call to call would make
// that attribution vary with it.
func Test_vendorAccessors_reportTheSameOrderEachCall(t *testing.T) {
	for _, name := range slices.Sorted(maps.Keys(vendorAccessors)) {
		t.Run(name, func(t *testing.T) {
			if !slices.Equal(vendorAccessors[name](), vendorAccessors[name]()) {
				t.Error("two calls report the patterns in different orders")
			}
		})
	}
}

// Test_vendorAccessors_safeForConcurrentCalls holds every accessor to being
// callable from more than one goroutine at once, which is the shape a
// per-request handler or a concurrent start-up path calls them in. Nothing
// else calls an accessor from more than one goroutine, so a registry or an
// accessor's slice built lazily behind a package-level variable would be
// reported by nothing else even under -race.
func Test_vendorAccessors_safeForConcurrentCalls(t *testing.T) {
	names := slices.Sorted(maps.Keys(vendorAccessors))

	want := make(map[string][]string, len(names))
	for _, name := range names {
		for _, p := range vendorAccessors[name]() {
			want[name] = append(want[name], p.Name())
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var bad []string
	for range 32 {
		wg.Go(func() {
			for _, name := range names {
				got := make([]string, 0, len(want[name]))
				for _, p := range vendorAccessors[name]() {
					got = append(got, p.Name())
				}
				if !slices.Equal(got, want[name]) {
					mu.Lock()
					bad = append(bad, name)
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()

	for _, name := range bad {
		t.Errorf("%s returned different patterns when called from another goroutine", name)
	}
}

// Test_vendorAccessors_unionMatchesAllBuiltinPatterns holds the union relation
// AllBuiltinPatterns's own doc comment states — every built-in pattern — against
// the exported function itself rather than against the unexported builtins
// slice Test_vendorAccessors_coverEveryBuiltin reads. The two can disagree only
// if AllBuiltinPatterns stops reporting the whole of builtins, which nothing
// else here would catch.
func Test_vendorAccessors_unionMatchesAllBuiltinPatterns(t *testing.T) {
	all := AllBuiltinPatterns()

	from := make(map[Pattern]string, len(all))
	for _, name := range slices.Sorted(maps.Keys(vendorAccessors)) {
		for _, p := range vendorAccessors[name]() {
			if !slices.Contains(all, p) {
				t.Errorf("%s returns %q, which AllBuiltinPatterns does not report", name, p.Name())
				continue
			}
			from[p] = name
		}
	}
	for _, p := range patternsWithNoVendor {
		if !slices.Contains(all, p) {
			t.Errorf("patternsWithNoVendor names %q, which AllBuiltinPatterns does not report", p.Name())
			continue
		}
		from[p] = "patternsWithNoVendor"
	}

	for _, p := range all {
		if _, ok := from[p]; !ok {
			t.Errorf("AllBuiltinPatterns reports %q, which is in no vendor accessor and not named in patternsWithNoVendor", p.Name())
		}
	}
}

// Test_vendorAccessors_patternsWithNoVendorIsExactly pins patternsWithNoVendor
// to the two names it holds today, so that a pattern belonging to a vendor
// added there instead of to a new accessor — the shortest path past
// Test_vendorAccessors_coverEveryBuiltin, which asks only that a pattern sit in
// one of the two tables and not which — is a line a reviewer reads rather than
// one that blends into it.
func Test_vendorAccessors_patternsWithNoVendorIsExactly(t *testing.T) {
	got := make([]string, len(patternsWithNoVendor))
	for i, p := range patternsWithNoVendor {
		got[i] = p.Name()
	}
	slices.Sort(got)

	want := []string{"jwt", "private-key"}
	if !slices.Equal(got, want) {
		t.Errorf("patternsWithNoVendor names %v; a pattern belonging here is a deliberate decision about its vendor and this test is where that decision is recorded — update want above alongside it", got)
	}
}

// vendorPatternPrefixExceptions names, for the few accessors whose vendor name
// and pattern names share no machine-derivable prefix, every pattern name that
// accessor is allowed to return, in the order it returns them. Every other
// accessor is held by prefix alone in
// Test_vendorAccessors_returnOnlyTheirOwnVendorsPatterns: lowercasing the
// accessor's name with "Patterns" trimmed must be the opening word of each
// pattern name it returns.
var vendorPatternPrefixExceptions = map[string][]string{
	"CratesIOPatterns":    {"crates-io-token"},
	"FlyIOPatterns":       {"fly-io-access-token"},
	"HashiCorpPatterns":   {"hashicorp-vault-token", "hcp-terraform-api-token"},
	"OnePasswordPatterns": {"1password-service-account-token"},
}

// Test_vendorAccessors_returnOnlyTheirOwnVendorsPatterns holds each accessor's
// name to the patterns it returns: nothing before this relates the two, so a
// pattern moved into the wrong accessor — one whose own accessor still names it
// too — passes Test_vendorAccessors_coverEveryBuiltin untouched, since that
// test asks only that every pattern sit in exactly one accessor and never
// which.
func Test_vendorAccessors_returnOnlyTheirOwnVendorsPatterns(t *testing.T) {
	for _, name := range slices.Sorted(maps.Keys(vendorAccessors)) {
		t.Run(name, func(t *testing.T) {
			if want, ok := vendorPatternPrefixExceptions[name]; ok {
				got := make([]string, 0, len(want))
				for _, p := range vendorAccessors[name]() {
					got = append(got, p.Name())
				}
				if !slices.Equal(got, want) {
					t.Errorf("returns %v; vendorPatternPrefixExceptions names %v", got, want)
				}
				return
			}

			slug := strings.ToLower(strings.TrimSuffix(name, "Patterns")) + "-"
			for _, p := range vendorAccessors[name]() {
				if !strings.HasPrefix(p.Name(), slug) {
					t.Errorf("returns %q, which does not begin with %q — a pattern belonging to another vendor, or a vendor slug not derivable from the accessor's name and needing an entry in vendorPatternPrefixExceptions", p.Name(), slug)
				}
			}
		})
	}
}

// Test_vendorAccessors_declaredOnlyInVendorsGo holds ".claude/rules
// /builtin-patterns.md"'s "Every vendor has an accessor of its own" to living
// in the one file that promise is about. An accessor written into a
// builtin_<name>.go beside its pattern instead — the natural mistake, since
// everything else about a pattern lives there — escapes
// Test_vendorAccessors_coverEveryBuiltin the moment every pattern it returns is
// already reachable through some accessor vendors.go does declare: it then
// gets no README row, is not counted in README's vendor total, and is held to
// neither freshness nor usability.
func Test_vendorAccessors_declaredOnlyInVendorsGo(t *testing.T) {
	_, files := sourceFiles(t)

	for name, f := range files {
		if !inPackage(f) || strings.HasSuffix(name, "_test.go") || name == "vendors.go" {
			continue
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
				continue
			}
			if fn.Name.Name == "AllBuiltinPatterns" {
				continue // the whole-registry accessor, not a vendor's
			}
			arr, ok := fn.Type.Results.List[0].Type.(*ast.ArrayType)
			if !ok {
				continue
			}
			if id, ok := arr.Elt.(*ast.Ident); ok && id.Name == "Pattern" {
				t.Errorf("%s returns []Pattern and is declared in %s; the vendor accessors live in vendors.go", fn.Name.Name, name)
			}
		}
	}
}

// Test_vendorAccessors_maskOnlyTheirOwnPatterns holds the exclusion half of
// "for a caller who wants some of them and not all" (README.md, "Usage"): a
// Masker built from one accessor's patterns must locate nothing that belongs
// to a pattern the accessor does not return. builtinPatterns (builtins_test.go)
// is what every built-in's samples are read from, so a sample here is one its
// own pattern is already held to locating.
func Test_vendorAccessors_maskOnlyTheirOwnPatterns(t *testing.T) {
	for _, name := range slices.Sorted(maps.Keys(vendorAccessors)) {
		t.Run(name, func(t *testing.T) {
			own := vendorAccessors[name]()
			m := New(WithPatterns(own...))

			for _, bp := range builtinPatterns {
				if slices.Contains(own, bp.pattern()) {
					continue
				}
				for _, s := range bp.samples {
					if got := m.Mask(s); got != s {
						t.Errorf("masking %q with only %s's own patterns changed it to %q; that text holds a %s value and %s does not return that pattern", s, name, got, bp.name, name)
					}
				}
			}
		})
	}
}
