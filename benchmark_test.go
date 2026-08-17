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
		{name: "no value", src: line},
		{name: "one value", src: line + "token=" + legacyToken("ghp_")},
		{name: "one value in a long line", src: strings.Repeat(line, 32) + "token=" + legacyToken("ghp_")},
		{name: "many values", src: strings.Repeat(line+"token="+legacyToken("ghp_")+"\n", 32)},
		{name: "overlapping values", src: "token=" + statelessToken()},
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
