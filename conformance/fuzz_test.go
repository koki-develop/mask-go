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
	"strings"
	"testing"

	"github.com/koki-develop/mask-go"
)

func FuzzMask(f *testing.F) {
	for _, c := range corpusCases(f) {
		f.Add(c.in)
	}
	// A string built from all 256 byte values, which is the one input
	// separatorFor (properties_test.go) has nothing left to mark redactions
	// with — masking.check's own fallback branch is otherwise reached only
	// by chance, after a fuzzer's mutations happen to cover every byte.
	var allBytes strings.Builder
	for b := range 256 {
		allBytes.WriteByte(byte(b))
	}
	f.Add(allBytes.String())
	f.Add("\xff\xfe")
	f.Add("日本語ghp_0123456789abcdefghijklmnopqrstuvwxyz日本語")
	f.Add("ghp_0123456789abcdefghijklmnopqrstuvwxyzghp_0123456789abcdefghijklmnopqrstuvwxyz")

	patterns := mask.AllBuiltinPatterns()
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
	f.Add("eyey")
	f.Add("user_id=")
	f.Add("日本語")
	f.Add("\xff\xfe")

	patterns := append(
		mask.AllBuiltinPatterns(),
		mask.MustRegexp("internal-token", `INT-[0-9a-f]{32}`),
		mask.MustRegexp("user-id", `user_id=(?P<mask>\d+)`),
		substringPattern("shared-secret", "0123456789abcdef0123456789abcdef"),
		substringPattern("one-byte", "e"),
		substringPattern("two-bytes", "ey"),
		hostileSpans,
	)
	f.Fuzz(func(t *testing.T, src string) {
		checkMasking(t, patterns, src)
	})
}
