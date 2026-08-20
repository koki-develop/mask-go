package mask

import (
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// builtinPatterns is what every built-in pattern is held to, one entry a
// pattern. A pattern added to builtins in builtins.go is added here as well,
// and the tests below then hold it to the properties every built-in shares, so
// that it arrives with them already in force rather than with each one written
// out by hand.
//
// The samples say only "this is one of these", which is all the properties
// need. What exactly is located, and what is left alone, is written out case by
// case in the builtin_<name>_test.go beside the pattern instead; the tables
// there stay the statement of behaviour and each of their cases still carries
// its own input.
var builtinPatterns = []struct {
	name    string              // what Name() must report
	pattern func() Pattern      // the exported accessor
	ref     func(string) []Span // the plain implementation the scan must agree with
	samples []string            // inputs holding a value of this kind
}{
	{
		name:    "aws-access-key-id",
		pattern: AWSAccessKeyID,
		ref:     referenceAWSAccessKeyIDFind,
		samples: []string{
			"AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF",
			"ASIA0123456789ABCDEF",
			"ASIAKIA0123456789ABCDEF",
			"AKIA0123456789ABCDEFASIA0123456789ABCDEF",
		},
	},
	{
		name:    "github-token",
		pattern: GitHubToken,
		ref:     referenceGitHubTokenFind,
		samples: []string{
			"GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
			"gho_0123456789abcdefghijklmnopqrstuvwxyz",
			"github_pat_0123456789abcdefABCDEF_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW",
			"ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			"ghu_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			"ghs_0123456789abcdefghijklmnopqrstuvwxyz0123_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
	},
	{
		name:    "jwt",
		pattern: JWT,
		ref:     referenceJWTFind,
		samples: []string{
			"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.",
			"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.encKEY123.iv12345.ciphertextABC.authTAGxyz",
			"eyIwIjoxLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
	},
	{
		name:    "slack-token",
		pattern: SlackToken,
		ref:     referenceSlackTokenFind,
		samples: []string{
			"SLACK_BOT_TOKEN=xoxb-0123456789ab-0123456789abc-0123456789abcdefghijklmn",
			"xoxp-0123456789ab-0123456789abc-0123456789abcd-0123456789abcdef0123456789abcdef",
			"xapp-1-A0123456789-0123456789abc-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"xwfp-0123456789ab-0123456789abcdefghijklmn",
			"xoxe-1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"xoxe.xoxb-1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"xoxb-xoxb-xoxb-xoxb-0123456789abcdefghijklmn",
		},
	},
}

// noValueInputs is text no built-in pattern has anything to find in: ordinary
// prose, and the bytes a scan reading one at a time can trip over.
var noValueInputs = []string{
	"",
	"a",
	"there is no credential in this sentence",
	"time=2026-08-17T00:00:00Z level=info msg=\"calling api\"",
	"\x00\x01\x02",
	"\xff\xfe", // not valid UTF-8
	"日本語",
	".",
	"..",
	"_",
	"-",
	"----------------------------------------",
}

// builtinInputs returns what a built-in is driven with: text holding no value
// at all, the samples the pattern named, and every prefix of each of them.
//
// The prefixes stand for the truncation a log line cut to a column limit
// leaves. A value cut short is where a scan reading past the end of its input,
// or resuming past what it has not consumed, shows itself.
func builtinInputs(samples []string) []string {
	inputs := slices.Clone(noValueInputs)
	for _, src := range samples {
		for i := range len(src) + 1 {
			inputs = append(inputs, src[:i])
		}
	}
	return inputs
}

// isPatternNameByte reports whether c may appear in the name of a pattern.
// Pattern.Name asks for a name that is stable, lowercase and hyphenated.
func isPatternNameByte(c byte) bool {
	return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-'
}

// Test_builtins_entriesAreFilledIn comes first in this file deliberately, so
// that it is the test which runs before the ones that would otherwise report a
// half-filled entry badly or not at all.
func Test_builtins_entriesAreFilledIn(t *testing.T) {
	// Every field of an entry is what one of the properties below is driven
	// from, and leaving a field out does not fail there. Six of the properties
	// read builtinInputs, which falls back to text holding no value where an
	// entry names no samples, and a property with nothing to find holds nothing:
	// a pattern locating only two bytes of a token and wired to the wrong
	// reference passes all six with samples omitted. A missing accessor or
	// reference is worse still, panicking and taking the rest of the package
	// down with it rather than failing one case.
	//
	// So an entry is held to being whole here, where the omission is reported as
	// itself. This is what the claim that a pattern arrives with the properties
	// in force rests on.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			if b.name == "" {
				t.Error("the entry names no pattern")
			}
			if b.pattern == nil {
				t.Error("the entry carries no accessor")
			}
			if b.ref == nil {
				t.Error("the entry carries no reference")
			}
			if len(b.samples) == 0 {
				t.Error("the entry carries no samples")
			}
		})
	}
}

func Test_builtins_matchAllBuiltinPatterns(t *testing.T) {
	// The table above and the registry in builtins.go must name the same
	// patterns in the same order. A pattern added to one and forgotten in the
	// other would otherwise either go untested or go unreported by
	// AllBuiltinPatterns, and neither shows anywhere else.
	got := AllBuiltinPatterns()
	if len(got) != len(builtinPatterns) {
		t.Fatalf("AllBuiltinPatterns() reports %d pattern(s), the table holds %d", len(got), len(builtinPatterns))
	}
	for i, b := range builtinPatterns {
		if got[i] != b.pattern() {
			t.Errorf("AllBuiltinPatterns()[%d] is %q, the table holds %q", i, got[i].Name(), b.name)
		}
	}
}

func Test_AllBuiltinPatterns_freshEachCall(t *testing.T) {
	first := AllBuiltinPatterns()
	first[0] = fixed("replaced")
	if second := AllBuiltinPatterns(); second[0] == first[0] {
		t.Error("modifying the returned slice changed what a later call returns")
	}
}

func Test_builtins_name(t *testing.T) {
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			if got := b.pattern().Name(); got != b.name {
				t.Errorf("Name() = %q, want %q", got, b.name)
			}

			// Pattern.Name asks for a name that is stable, lowercase and
			// hyphenated, and a caller keying on one reads it as such. Nothing
			// enforced that before, so each new name was only as conventional
			// as whoever wrote it.
			if b.name == "" {
				t.Fatal("the name is empty")
			}
			for _, c := range []byte(b.name) {
				if !isPatternNameByte(c) {
					t.Errorf("name %q holds %q, want lowercase letters, digits and hyphens", b.name, c)
				}
			}
			if strings.HasPrefix(b.name, "-") || strings.HasSuffix(b.name, "-") {
				t.Errorf("name %q opens or closes with a hyphen", b.name)
			}
		})
	}
}

func Test_builtins_sameValueEachCall(t *testing.T) {
	// Match carries the Pattern itself, so a caller comparing one against a
	// built-in must get the same value every call. An accessor returning a
	// pattern built on the spot would compare equal to nothing.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			if first, second := b.pattern(), b.pattern(); first != second {
				t.Error("the accessor returned a different value on a second call")
			}
		})
	}
}

func Test_builtins_locateTheirSamples(t *testing.T) {
	// The properties below say what must hold of a located value, which says
	// nothing at all where a sample holds none. Every sample is held to being
	// what it claims first, so that the rest cannot pass vacuously.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			if len(b.samples) == 0 {
				t.Fatal("the entry carries no samples, so nothing below holds anything")
			}
			for _, src := range b.samples {
				if got := b.pattern().Find(src); len(got) == 0 {
					t.Errorf("Find(%q) located nothing, want a value", src)
				}
			}
		})
	}
}

func Test_builtins_findNothingWithoutAValue(t *testing.T) {
	// The other side of the same coin: a pattern eager enough to fire on prose
	// or on a run of punctuation redacts what a caller wanted to keep, and the
	// per-pattern tables only rule out the false positives their author thought
	// of.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			for _, src := range noValueInputs {
				if got := b.pattern().Find(src); len(got) != 0 {
					t.Errorf("Find(%q) = %v, want no span", src, got)
				}
			}
		})
	}
}

func Test_builtins_reportUsableSpans(t *testing.T) {
	// Find is documented to have spans reaching outside src, and spans whose
	// Start is not less than their End, ignored rather than trusted, and
	// Masker.locate duly drops them. A built-in reporting one would therefore
	// go unnoticed there, so the built-ins are held to reporting none.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			p := b.pattern()
			for _, src := range builtinInputs(b.samples) {
				for _, s := range p.Find(src) {
					if s.Start < 0 || s.End > len(src) || s.Start >= s.End {
						t.Errorf("Find(%q) reported %v, unusable in %d bytes", src, s, len(src))
					}
				}
			}
		})
	}
}

func Test_builtins_matchTheirReference(t *testing.T) {
	// The fuzz target each pattern keeps holds its scan to its reference on
	// generated input, which only a run with -fuzz reaches beyond the corpus.
	// The same holds on the samples and their prefixes under a plain go test,
	// so that a reference wired up to the wrong pattern, or one left behind by
	// a change to the scan, is caught without fuzzing being run at all.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			if b.ref == nil {
				// Calling through a nil reference panics, which takes the rest
				// of the package down instead of failing this one entry.
				t.Fatalf("the entry for %q carries no reference", b.name)
			}
			p := b.pattern()
			for _, src := range builtinInputs(b.samples) {
				got, want := p.Find(src), b.ref(src)
				if !slices.Equal(got, want) {
					t.Errorf("Find(%q) = %v, reference gives %v", src, got, want)
				}
			}
		})
	}
}

func Test_builtins_maskLeavesNothingToFind(t *testing.T) {
	// What Mask returns must hold no value the same patterns can still find: a
	// built-in locating only part of a value leaves the rest to be found again.
	// Each pattern is driven alone and beside the others, because a value one
	// pattern locates whole can be one another locates in part, which is how a
	// stateless installation token holds a JWT.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			maskers := map[string]*Masker{
				"alone":           New(WithPatterns(b.pattern())),
				"with the others": New(WithPatterns(AllBuiltinPatterns()...)),
			}
			for name, m := range maskers {
				t.Run(name, func(t *testing.T) {
					for _, src := range builtinInputs(b.samples) {
						masked := m.Mask(src)
						if left := m.locate(masked); len(left) != 0 {
							t.Errorf("Mask(%q) = %q still holds %d value(s) to redact", src, masked, len(left))
						}
						if again := m.Mask(masked); again != masked {
							t.Errorf("Mask is not idempotent on %q: %q then %q", src, masked, again)
						}
					}
				})
			}
		})
	}
}

func Test_builtins_concurrentUse(t *testing.T) {
	// Pattern is documented safe for concurrent use, and both built-in scans
	// carry a cursor as they go, one of them a decoder as well. Driving a
	// pattern from many goroutines at once puts what it carries under the race
	// detector, and holds its answer to the one a single goroutine gets.
	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			p := b.pattern()
			inputs := builtinInputs(b.samples)
			want := make([][]Span, len(inputs))
			for i, src := range inputs {
				want[i] = p.Find(src)
			}

			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					for range 4 {
						for i, src := range inputs {
							if got := p.Find(src); !slices.Equal(got, want[i]) {
								t.Errorf("Find(%q) = %v, want %v", src, got, want[i])
								return
							}
						}
					}
				})
			}
			wg.Wait()
		})
	}
}

func Test_builtins_scanIsLinear(t *testing.T) {
	// A scan working out again at every candidate what belongs to the run it
	// sits in costs time quadratic in the length of the input, which has
	// happened in this package more than once. Every sample is repeated to a
	// length at which a quadratic scan cannot finish and a linear one is not
	// noticed, so a new pattern is guarded without anyone writing the guard.
	//
	// The inputs crafted against what a particular scan remembers stay with
	// that scan, in Test_JWT_scanIsLinear: nothing generic reaches a header
	// that reads as JSON to its very end.
	// Two mebibytes is what separates the two costs here rather than merely
	// suggesting a difference. Defeating the run cursor the GitHub scan keeps
	// takes a sample repeated to this length from twelve milliseconds to
	// twenty-one seconds, where at a quarter of a mebibyte it takes it only to
	// a third of a second and passes a bound of any use. The limit is a
	// hundredfold above a linear scan and a tenth of a quadratic one.
	const (
		size  = 2 << 20
		limit = 2 * time.Second
	)

	for _, b := range builtinPatterns {
		t.Run(b.name, func(t *testing.T) {
			m := New(WithPatterns(b.pattern()))
			for _, sample := range b.samples {
				// Beside the sample repeated whole, a sample cut in half is
				// repeated too. A value that never completes is what leaves a
				// scan resuming one byte along, candidate after candidate,
				// which is where the quadratic cost lives.
				for _, unit := range []string{sample, sample[:len(sample)/2]} {
					if unit == "" {
						continue
					}
					src := strings.Repeat(unit, size/len(unit)+1)
					start := time.Now()
					_ = m.Mask(src)
					if d := time.Since(start); d > limit {
						t.Errorf("Mask() of %d bytes of %q took %v", len(src), unit, d)
					}
				}
			}
		})
	}
}
