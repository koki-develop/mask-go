package mask

import (
	"strings"
	"testing"
)

func BenchmarkMasker_Mask(b *testing.B) {
	m := New(WithPatterns(DefaultPatterns()...))
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.github.com/user `

	benchmarks := []struct {
		name string
		src  string
	}{
		{
			name: "no value",
			src:  line,
		},
		{
			name: "one value",
			src:  line + "token=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "one value in a long line",
			src:  strings.Repeat(line, 32) + "token=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name: "many values",
			src:  strings.Repeat(line+"token=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n", 32),
		},
		{
			// The stateless installation token holds a JWT, so both built-in
			// patterns fire on it.
			name: "overlapping values",
			src:  "token=ghs_123456_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ.0123456789abcdef",
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.SetBytes(int64(len(bm.src)))
			b.ReportAllocs()
			for b.Loop() {
				_ = m.Mask(bm.src)
			}
		})
	}
}
