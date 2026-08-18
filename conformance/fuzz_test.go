// Fuzzing the library as a caller has it.
//
// The corpus seeds this: every case is a starting point the fuzzer mutates, so
// the inputs generated here begin at credentials rather than at random bytes,
// and the properties held to are the ones that must hold of masking anything at
// all. The white-box targets in the root package fuzz what is inside — the merge
// a Masker does, and each scanner against the reference beside it — and this one
// fuzzes what is outside.

package conformance

import (
	"testing"

	"github.com/koki-develop/mask-go"
)

func FuzzMask(f *testing.F) {
	for _, c := range corpusCases(f) {
		f.Add(c.in)
	}

	patterns := mask.DefaultPatterns()
	f.Fuzz(func(t *testing.T, src string) {
		checkMasking(t, patterns, src)
	})
}

func FuzzMask_customPatterns(f *testing.F) {
	// A caller's patterns reach the same merge the built-in ones do, and a
	// pattern of a caller's is under no obligation to be careful: it may report
	// spans that overlap, that repeat, that are empty or that reach outside the
	// text. None of that may leave a Masker returning text that is not the text
	// it was given with values redacted.
	for _, c := range corpusCases(f) {
		f.Add(c.in)
	}

	patterns := append(
		mask.DefaultPatterns(),
		mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`),
		mask.MustRegexp("user-id", `user_id=(?P<mask>\d+)`),
		substringPattern("shared-secret", "s3cr3t-value"),
		substringPattern("one-byte", "e"),
		substringPattern("two-bytes", "ey"),
	)
	f.Fuzz(func(t *testing.T, src string) {
		checkMasking(t, patterns, src)
	})
}
