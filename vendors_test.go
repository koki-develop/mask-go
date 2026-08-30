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
	"CircleCIPatterns":     CircleCIPatterns,
	"CloudflarePatterns":   CloudflarePatterns,
	"CratesIOPatterns":     CratesIOPatterns,
	"DatabricksPatterns":   DatabricksPatterns,
	"DigitalOceanPatterns": DigitalOceanPatterns,
	"DockerPatterns":       DockerPatterns,
	"DopplerPatterns":      DopplerPatterns,
	"DynatracePatterns":    DynatracePatterns,
	"GitHubPatterns":       GitHubPatterns,
	"GitLabPatterns":       GitLabPatterns,
	"GooglePatterns":       GooglePatterns,
	"GrafanaPatterns":      GrafanaPatterns,
	"GroqPatterns":         GroqPatterns,
	"HashiCorpPatterns":    HashiCorpPatterns,
	"HerokuPatterns":       HerokuPatterns,
	"HuggingFacePatterns":  HuggingFacePatterns,
	"LinearPatterns":       LinearPatterns,
	"NotionPatterns":       NotionPatterns,
	"NPMPatterns":          NPMPatterns,
	"OnePasswordPatterns":  OnePasswordPatterns,
	"OpenAIPatterns":       OpenAIPatterns,
	"OpenRouterPatterns":   OpenRouterPatterns,
	"PlanetScalePatterns":  PlanetScalePatterns,
	"PostmanPatterns":      PostmanPatterns,
	"PulumiPatterns":       PulumiPatterns,
	"PyPIPatterns":         PyPIPatterns,
	"ReplicatePatterns":    ReplicatePatterns,
	"ResendPatterns":       ResendPatterns,
	"RubyGemsPatterns":     RubyGemsPatterns,
	"SendGridPatterns":     SendGridPatterns,
	"SentryPatterns":       SentryPatterns,
	"ShopifyPatterns":      ShopifyPatterns,
	"SlackPatterns":        SlackPatterns,
	"SonarQubePatterns":    SonarQubePatterns,
	"SourcegraphPatterns":  SourcegraphPatterns,
	"StripePatterns":       StripePatterns,
	"SupabasePatterns":     SupabasePatterns,
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
