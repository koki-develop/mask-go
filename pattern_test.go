package mask

import (
	"reflect"
	"testing"
)

func Test_NewPattern(t *testing.T) {
	want := []Span{{1, 2}}
	var got string
	p := NewPattern("custom", func(src string) []Span {
		got = src
		return want
	})

	if p.Name() != "custom" {
		t.Errorf("Name() = %q, want %q", p.Name(), "custom")
	}
	if spans := p.Find("abcdef"); !reflect.DeepEqual(spans, want) {
		t.Errorf("Find() = %v, want %v", spans, want)
	}
	if got != "abcdef" {
		t.Errorf("find received %q, want %q", got, "abcdef")
	}
}

func Test_NewPattern_comparable(t *testing.T) {
	// Match carries a Pattern, so == on one must never panic.
	p, q := NewPattern("a", nil), NewPattern("b", nil)
	if p == q {
		t.Error("distinct patterns compared equal")
	}
	if p != p { //nolint:staticcheck // the point is that == is defined
		t.Error("a pattern did not compare equal to itself")
	}
}

func Test_MustRegexp_find(t *testing.T) {
	tests := []struct {
		name string
		expr string
		src  string
		want []Span
	}{
		{
			name: "whole match",
			expr: `\d+`,
			src:  "a12b",
			want: []Span{{1, 3}},
		},
		{
			name: "every match",
			expr: `\d+`,
			src:  "a1b22c333",
			want: []Span{{1, 2}, {3, 5}, {6, 9}},
		},
		{
			name: "no match",
			expr: `\d+`,
			src:  "abc",
			want: []Span{},
		},
		{
			name: "mask group narrows the span",
			expr: `id=(?P<mask>\d+)`,
			src:  "id=123 name=a",
			want: []Span{{3, 6}},
		},
		{
			name: "mask group in every match",
			expr: `id=(?P<mask>\d+)`,
			src:  "id=1 id=22",
			want: []Span{{3, 4}, {8, 10}},
		},
		{
			name: "unnamed groups do not narrow the span",
			expr: `id=(\d+)`,
			src:  "id=123",
			want: []Span{{0, 6}},
		},
		{
			name: "a group named otherwise does not narrow the span",
			expr: `id=(?P<value>\d+)`,
			src:  "id=123",
			want: []Span{{0, 6}},
		},
		{
			name: "a mask group taking part in no match is skipped",
			expr: `id=(?:(?P<mask>\d+)|none)`,
			src:  "id=none id=12",
			want: []Span{{11, 13}},
		},
		{
			name: "an empty mask group yields an empty span",
			expr: `id=(?P<mask>\d*)`,
			src:  "id=",
			want: []Span{{3, 3}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MustRegexp("p", tt.expr).Find(tt.src)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_MustRegexp_name(t *testing.T) {
	if got := MustRegexp("my-pattern", `x`).Name(); got != "my-pattern" {
		t.Errorf("Name() = %q, want %q", got, "my-pattern")
	}
}

func Test_MustRegexp_invalidExpression(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustRegexp did not panic on an invalid expression")
		}
	}()
	MustRegexp("p", `(`)
}

func Test_MustRegexp_maskGroup(t *testing.T) {
	m := New(WithPatterns(MustRegexp("user-id", `user_id=(?P<mask>\d+)`)))
	if got, want := m.Mask("user_id=12345 name=alice"), "user_id=***** name=alice"; got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}
