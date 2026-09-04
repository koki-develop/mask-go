package mask

import (
	"slices"
	"sync"
	"testing"
)

func Test_WithPatterns_accumulates(t *testing.T) {
	m := New(
		WithPatterns(fixed("a", Span{0, 2})),
		WithPatterns(fixed("b", Span{4, 6})),
		WithRedactor(naming),
	)
	if got, want := m.Mask("abcdef"), "<a>cd<b>"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func Test_WithPatterns_order(t *testing.T) {
	m := New(
		WithPatterns(fixed("a", Span{0, 6})),
		WithPatterns(fixed("b", Span{0, 6})),
		WithRedactor(naming),
	)
	if got, want := m.Mask("abcdef"), "<a>"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func Test_WithPatterns_noArguments(t *testing.T) {
	if got, want := New(WithPatterns()).Mask("abcdef"), "abcdef"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func Test_WithRedactor(t *testing.T) {
	m := New(WithPatterns(fixed("p", Span{0, 3})), WithRedactor(Fixed("X")))
	if got, want := m.Mask("abcdef"), "Xdef"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func Test_WithRedactor_lastWins(t *testing.T) {
	m := New(
		WithPatterns(fixed("p", Span{0, 3})),
		WithRedactor(Fixed("X")),
		WithRedactor(Fixed("Y")),
	)
	if got, want := m.Mask("abcdef"), "Ydef"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func Test_WithPatterns_zeroArgumentCallIsHarmless(t *testing.T) {
	t.Run("an empty WithPatterns call between two others", func(t *testing.T) {
		m := New(
			WithPatterns(fixed("a", Span{0, 2})),
			WithPatterns(),
			WithPatterns(fixed("b", Span{4, 6})),
			WithRedactor(naming),
		)
		if got, want := m.Mask("abcdef"), "<a>cd<b>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})

	t.Run("a nil slice spread into WithPatterns between two others", func(t *testing.T) {
		var none []Pattern
		m := New(
			WithPatterns(fixed("a", Span{0, 2})),
			WithPatterns(none...),
			WithPatterns(fixed("b", Span{4, 6})),
			WithRedactor(naming),
		)
		if got, want := m.Mask("abcdef"), "<a>cd<b>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})
}

// Test_WithPatterns_tieBreakAcrossTwoCallsIgnoresName holds the tie-break rule
// ("the one added first by WithPatterns") to a caller who splits registration
// across two calls with the later-added pattern carrying the name that would
// win if names decided anything: mask_test.go rules the name out within one
// call, and this rules it out across two.
func Test_WithPatterns_tieBreakAcrossTwoCallsIgnoresName(t *testing.T) {
	m := New(
		WithPatterns(fixed("z", Span{0, 6})),
		WithPatterns(fixed("a", Span{0, 6})),
		WithRedactor(naming),
	)
	if got, want := m.Mask("abcdef"), "<z>"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

func Test_WithPatterns_accumulatesAcrossMoreThanTwoCalls(t *testing.T) {
	t.Run("three disjoint values from three separate calls", func(t *testing.T) {
		m := New(
			WithPatterns(fixed("a", Span{0, 2})),
			WithPatterns(fixed("b", Span{2, 4})),
			WithPatterns(fixed("c", Span{4, 6})),
			WithRedactor(naming),
		)
		if got, want := m.Mask("abcdef"), "<a><b><c>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})

	t.Run("a tie among three ties on the first call", func(t *testing.T) {
		m := New(
			WithPatterns(fixed("a", Span{0, 6})),
			WithPatterns(fixed("b", Span{0, 6})),
			WithPatterns(fixed("c", Span{0, 6})),
			WithRedactor(naming),
		)
		if got, want := m.Mask("abcdef"), "<a>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})

	t.Run("reversing the order of three calls reverses the tie", func(t *testing.T) {
		m := New(
			WithPatterns(fixed("c", Span{0, 6})),
			WithPatterns(fixed("b", Span{0, 6})),
			WithPatterns(fixed("a", Span{0, 6})),
			WithRedactor(naming),
		)
		if got, want := m.Mask("abcdef"), "<c>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})
}

// Test_New_doesNotDependOnTheCallersPatternSlice holds a Masker to being
// "fixed once created" against the one slice that invites a caller to keep
// writing to it: WithPatterns' own doc example builds one, and
// AllBuiltinPatterns says its result "may be modified by the caller".
// Whatever New reads out of the slice it is given, it must not go on reading
// the slice itself.
func Test_New_doesNotDependOnTheCallersPatternSlice(t *testing.T) {
	t.Run("overwriting elements after New", func(t *testing.T) {
		ps := []Pattern{fixed("a", Span{0, 2}), fixed("b", Span{4, 6})}
		m := New(WithPatterns(ps...), WithRedactor(naming))
		ps[0], ps[1] = fixed("z", Span{0, 6}), nil
		if got, want := m.Mask("abcdef"), "<a>cd<b>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})

	t.Run("reordering elements after New does not move attribution", func(t *testing.T) {
		ps := []Pattern{fixed("a", Span{0, 2}), fixed("b", Span{4, 6})}
		m := New(WithPatterns(ps...), WithRedactor(naming))
		slices.Reverse(ps)
		if got, want := m.Mask("abcdef"), "<a>cd<b>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})

	t.Run("clearing the slice after New", func(t *testing.T) {
		ps := []Pattern{fixed("a", Span{0, 2}), fixed("b", Span{4, 6})}
		m := New(WithPatterns(ps...), WithRedactor(naming))
		clear(ps)
		if got, want := m.Mask("abcdef"), "<a>cd<b>"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})
}

// Test_WithPatterns_secondCallDoesNotWriteIntoTheFirstsSpareCapacity holds
// WithPatterns to leaving a caller's slice alone even where append could grow
// it in place: ps here has spare capacity a naive append(o.patterns,
// patterns...) could write into, corrupting what the caller's own slice header
// still calls its length.
func Test_WithPatterns_secondCallDoesNotWriteIntoTheFirstsSpareCapacity(t *testing.T) {
	ps := make([]Pattern, 1, 4)
	ps[0] = fixed("a", Span{0, 2})
	full := ps[:cap(ps)] // aliases ps's backing array past its own length

	m := New(WithPatterns(ps...), WithPatterns(fixed("b", Span{4, 6})), WithRedactor(naming))
	if got, want := m.Mask("abcdef"), "<a>cd<b>"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
	for i := 1; i < len(full); i++ {
		if full[i] != nil {
			t.Errorf("full[%d] = %v, want nil: a second WithPatterns call wrote into the first's spare capacity", i, full[i])
		}
	}
}

// Test_New_optionValueIsIndependentAcrossCalls holds one Option value handed
// to two New calls to building two independent Maskers, neither able to see
// what the other's call added nor to be changed by it afterwards — the shape
// a package-level "defaults" Option reaches.
func Test_New_optionValueIsIndependentAcrossCalls(t *testing.T) {
	base := WithPatterns(fixed("a", Span{0, 2}))

	m1 := New(base, WithPatterns(fixed("b", Span{2, 4})), WithRedactor(naming))
	want1 := "<a><b>ef"
	if got := m1.Mask("abcdef"); got != want1 {
		t.Errorf("m1.Mask() = %q, want %q", got, want1)
	}

	m2 := New(base, WithPatterns(fixed("c", Span{4, 6})), WithRedactor(naming))
	want2 := "<a>cd<c>"
	if got := m2.Mask("abcdef"); got != want2 {
		t.Errorf("m2.Mask() = %q, want %q", got, want2)
	}

	if got := m1.Mask("abcdef"); got != want1 {
		t.Errorf("m1.Mask() after building m2 from the same base = %q, want %q", got, want1)
	}
}

// Test_New_concurrentFromSharedOption drives New itself, not only Mask, from
// many goroutines sharing one Option value — the shape of building one Masker
// per request handler from a package-level defaults slice.
func Test_New_concurrentFromSharedOption(t *testing.T) {
	opts := []Option{WithPatterns(fixed("a", Span{0, 2})), WithRedactor(naming)}

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 32 {
				if got, want := New(opts...).Mask("abcdef"), "<a>cdef"; got != want {
					t.Errorf("New(opts...).Mask() = %q, want %q", got, want)
				}
			}
		})
	}
	wg.Wait()
}

// Test_WithPatterns_samePatternValueTwice holds the merge and tie-break rules
// to the case where the two tied entries are not merely two patterns tied on
// a span but the same Pattern value: the redactor sees it once and
// Match.Pattern is that one instance, whichever of the two registrations
// counts as "first".
func Test_WithPatterns_samePatternValueTwice(t *testing.T) {
	p := fixed("dup", Span{2, 4})

	tests := []struct {
		name string
		opts []Option
	}{
		{name: "one WithPatterns call listing it twice", opts: []Option{WithPatterns(p, p)}},
		{name: "two separate WithPatterns calls each giving it once", opts: []Option{WithPatterns(p), WithPatterns(p)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			var gotPattern Pattern
			r := NewRedactor(func(m Match) string {
				calls++
				gotPattern = m.Pattern
				return "X"
			})
			m := New(append(tt.opts, WithRedactor(r))...)
			if got, want := m.Mask("abcdef"), "abXef"; got != want {
				t.Errorf("Mask() = %q, want %q", got, want)
			}
			if calls != 1 {
				t.Errorf("redactor called %d times, want 1", calls)
			}
			if gotPattern != p {
				t.Errorf("Match.Pattern = %v, want the same instance registered twice", gotPattern)
			}
		})
	}
}

// Test_WithPatterns_builtinPatternGivenTwice holds the same rule at the size a
// caller actually reaches it at: append(mask.AllBuiltinPatterns(),
// mask.GitHubToken()), or two option lists that both ask for the builtins,
// redacts no differently from registering the pattern once.
func Test_WithPatterns_builtinPatternGivenTwice(t *testing.T) {
	src := "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	once := New(WithPatterns(GitHubToken())).Mask(src)

	t.Run("the accessor's value given twice", func(t *testing.T) {
		if got := New(WithPatterns(GitHubToken(), GitHubToken())).Mask(src); got != once {
			t.Errorf("Mask() = %q, want %q (same as registering it once)", got, once)
		}
	})

	t.Run("AllBuiltinPatterns given twice", func(t *testing.T) {
		m := New(WithPatterns(AllBuiltinPatterns()...), WithPatterns(AllBuiltinPatterns()...))
		if got := m.Mask(src); got != once {
			t.Errorf("Mask() = %q, want %q (same as registering the builtins once)", got, once)
		}
	})
}

// Test_WithPatterns_patternsSharingAName holds attribution to Pattern
// identity rather than to Name: Name identifies a pattern to a caller and a
// redactor, not to the Masker, so two patterns reporting the same Name() are
// still resolved, and reported to a redactor, by which one they are.
func Test_WithPatterns_patternsSharingAName(t *testing.T) {
	a := fixed("dup", Span{0, 4})
	b := fixed("dup", Span{0, 4})

	record := func() (r Redactor, got *[]Pattern) {
		got = new([]Pattern)
		r = NewRedactor(func(m Match) string {
			*got = append(*got, m.Pattern)
			return "X"
		})
		return r, got
	}

	t.Run("a tie on the same span goes to the instance added first", func(t *testing.T) {
		r, got := record()
		if out := New(WithPatterns(a, b), WithRedactor(r)).Mask("abcdef"); out != "Xef" {
			t.Errorf("Mask() = %q, want %q", out, "Xef")
		}
		if len(*got) != 1 || (*got)[0] != a {
			t.Errorf("Match.Pattern = %v, want [%v] (added first)", *got, a)
		}
	})

	t.Run("reversed registration attributes the other instance", func(t *testing.T) {
		r, got := record()
		New(WithPatterns(b, a), WithRedactor(r)).Mask("abcdef")
		if len(*got) != 1 || (*got)[0] != b {
			t.Errorf("Match.Pattern = %v, want [%v] (added first)", *got, b)
		}
	})

	t.Run("two disjoint spans sharing a name are both scanned and correctly attributed", func(t *testing.T) {
		c := fixed("dup", Span{0, 2})
		d := fixed("dup", Span{4, 6})
		r, got := record()
		if out := New(WithPatterns(c), WithPatterns(d), WithRedactor(r)).Mask("abcdef"); out != "XcdX" {
			t.Errorf("Mask() = %q, want %q", out, "XcdX")
		}
		if len(*got) != 2 || (*got)[0] != c || (*got)[1] != d {
			t.Errorf("Match.Pattern sequence = %v, want [%v %v]", *got, c, d)
		}
	})
}

// Test_WithPatterns_onlyUnusableSpansBesideARealOne holds a pattern reporting
// nothing but ignored spans to winning no attribution from a pattern reporting
// the real value, when the two arrive through two separate WithPatterns
// calls rather than one — mask_test.go's TestMasker_Mask_attribution already
// holds the same rule for the two given in a single call.
func Test_WithPatterns_onlyUnusableSpansBesideARealOne(t *testing.T) {
	bad := fixed("bad", Span{4, 7}, Span{3, 3}, Span{-1, 2})
	good := fixed("good", Span{0, 2})

	t.Run("the pattern reporting only ignored spans registered first", func(t *testing.T) {
		m := New(WithPatterns(bad), WithPatterns(good), WithRedactor(naming))
		if got, want := m.Mask("abcdef"), "<good>cdef"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})

	t.Run("the same, registered second", func(t *testing.T) {
		m := New(WithPatterns(good), WithPatterns(bad), WithRedactor(naming))
		if got, want := m.Mask("abcdef"), "<good>cdef"; got != want {
			t.Errorf("Mask() = %q, want %q", got, want)
		}
	})
}

// Test_WithPatterns_emptyName drives a Pattern whose Name is the empty
// string — reachable from NewPattern(cfg.Name, ...) with the name left out of
// a config file — through a Masker and a redactor that reads it back.
func Test_WithPatterns_emptyName(t *testing.T) {
	p := NewPattern("", func(src string) ([]Span, int) { return []Span{{0, 3}}, len(src) })
	m := New(WithPatterns(p), WithRedactor(naming))
	if got, want := m.Mask("abcdef"), "<>def"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}
