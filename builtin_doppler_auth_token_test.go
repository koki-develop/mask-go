package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Doppler auth token pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The tokens written out below are made only of ordered characters: valid in
// shape, obviously not real. A body is forty to forty-four letters and digits,
// so 0123456789abcdef twice over and eleven more is the forty-three characters
// Doppler's own examples run to, and the same run cut shorter or longer is a
// body at either end of the range.

func Test_DopplerAuthToken(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a cli token",
			src:  "dp.ct.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 49}},
		},
		{
			name: "a personal token in an environment assignment",
			src:  "DOPPLER_TOKEN=dp.pt.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{14, 63}},
		},
		{
			name: "a service token written without an environment segment",
			src:  "dp.st.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 49}},
		},
		{
			name: "a service token carrying the environment it was cut for",
			src:  "dp.st.dev.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 53}},
		},
		{
			name: "a service account token",
			src:  "dp.sa.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 49}},
		},
		{
			name: "a service account identity token",
			src:  "dp.said.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 51}},
		},
		{
			name: "a scim token",
			src:  "dp.scim.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 51}},
		},
		{
			name: "an audit token",
			src:  "dp.audit.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 52}},
		},
		{
			name: "a body at the shortest the vendor admits",
			src:  "dp.pt.0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 46}},
		},
		{
			name: "a body at the longest the vendor admits",
			src:  "dp.pt.0123456789abcdef0123456789abcdef0123456789ab",
			want: []Span{{0, 50}},
		},
		{
			// The maximum is a cut, so what runs on past it is not part of the
			// token and stays in the text.
			name: "a run longer than the widest body is a token and what follows it",
			src:  "dp.pt.0123456789abcdef0123456789abcdef0123456789abc",
			want: []Span{{0, 50}},
		},
		{
			name: "two tokens with nothing between them",
			src:  "dp.pt.0123456789abcdef0123456789abcdef0123456789abdp.audit.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 50}, {50, 102}},
		},
		{
			// And the same pair with the first body a character short of the
			// cut, where the run carries on into the second token's opening: the
			// cut falls inside it, the two spans overlap and a Masker resolves
			// them into one.
			name: "a body short of the cut written against another token",
			src:  "dp.pt.0123456789abcdef0123456789abcdef0123456789adp.audit.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 50}, {49, 101}},
		},
		{
			name: "a token in the header the api reads it from",
			src:  "Authorization: Bearer dp.pt.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{22, 71}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DopplerAuthToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DopplerAuthToken_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a prefix alone",
			src:  "dp.pt.",
		},
		{
			name: "a body one character short of the shortest",
			src:  "dp.pt.0123456789abcdef0123456789abcdef0123456",
		},
		{
			name: "a body carrying a space",
			src:  "dp.pt.0123456789abcdef 123456789abcdef0123456789a",
		},
		{
			name: "a body carrying a hyphen",
			src:  "dp.pt.0123456789abcdef-123456789abcdef0123456789a",
		},
		{
			name: "a body carrying an underscore",
			src:  "dp.pt.0123456789abcdef_123456789abcdef0123456789a",
		},
		{
			name: "a body carrying a separator",
			src:  "dp.pt.0123456789abcdef.123456789abcdef0123456789a",
		},
		{
			// The characters above all stand in the middle of a body. These
			// four stand at its first character, straight behind the prefix,
			// where the same rejection holds and no segment reading rescues a
			// personal token.
			name: "a hyphen where the body opens",
			src:  "dp.pt.-0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a space where the body opens",
			src:  "dp.pt. 0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "an underscore where the body opens",
			src:  "dp.pt._0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a separator where the body opens",
			src:  "dp.pt..0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a kind Doppler names no format for",
			src:  "dp.xx.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			// A proper prefix of a real kind, rather than a kind Doppler simply
			// never wrote: "sai" opens "said" but is not it.
			name: "a kind that is a proper prefix of a real one",
			src:  "dp.sai.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "another kind that opens a real one",
			src:  "dp.audi.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			// A real kind with one character added rather than removed.
			name: "a real kind with a character added",
			src:  "dp.saidx.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			// Six characters, past the widest kind Doppler names, so the walk
			// bounded at that width never reaches the separator that would
			// close this one.
			name: "a kind wider than the widest there is",
			src:  "dp.audits.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a kind with no separator closing it",
			src:  "dp.pt0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "an empty kind",
			src:  "dp..0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "an uppercase prefix",
			src:  "DP.PT.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			// The kind in capitals rather than the whole prefix.
			name: "a kind in capitals",
			src:  "dp.PT.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "the literal in capitals",
			src:  "DP.pt.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "the opening without the separator behind it",
			src:  "dppt.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a body of the right length opening with no prefix",
			src:  "xxxxxx0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DopplerAuthToken().Find(tt.src); got != nil {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_DopplerAuthToken_inContext(t *testing.T) {
	// The places a token is written: the environment variable the CLI and every
	// integration reads one from, the header the API takes it in, the file the
	// CLI stores it in, and the command lines that pass it along.
	const token = "dp.st.dev.0123456789abcdef0123456789abcdef0123456789a"

	tests := []struct {
		name  string
		src   string
		start int
	}{
		{
			name:  "a token in a dotenv line",
			src:   "DOPPLER_TOKEN=" + token,
			start: 14,
		},
		{
			name:  "a token in the authorization header",
			src:   "Authorization: Bearer " + token,
			start: 22,
		},
		{
			name:  "a token on a curl command line",
			src:   `curl -H "Authorization: Bearer ` + token + `" https://api.doppler.com/v3/configs`,
			start: 31,
		},
		{
			name:  "a token in the yaml the cli stores one in",
			src:   "scoped:\n  /:\n    token: " + token,
			start: 24,
		},
		{
			name:  "a token in the json a token list returns",
			src:   `{"name":"ci","slug":"acme","key":"` + token + `"}`,
			start: 34,
		},
		{
			name:  "a token on the command line that creates one",
			src:   "doppler run --token " + token + " -- ./deploy.sh",
			start: 20,
		},
		{
			name:  "a token at the end of a sentence",
			src:   "the token is " + token + ".",
			start: 13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := []Span{{tt.start, tt.start + len(token)}}
			if got, _ := DopplerAuthToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_DopplerAuthToken_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a token is
	// written against a word character, and one behind it would drop a token
	// followed by a character of the body's own alphabet. Every ruleset reading
	// this format asks for one on both sides.
	const token = "dp.pt.0123456789abcdef0123456789abcdef0123456789a"

	tests := []struct {
		name  string
		src   string
		start int
	}{
		{
			name:  "a token after an underscore",
			src:   "DOPPLER_TOKEN_" + token,
			start: 14,
		},
		{
			name:  "a token after a letter",
			src:   "x" + token,
			start: 1,
		},
		{
			name:  "a word written against a token",
			src:   token + "-suffix",
			start: 0,
		},
		{
			// A multi-byte rune written immediately in front, rather than
			// separated by a space as every corpus affix writes one. Neither
			// UTF-8 encoding shares a byte with the prefix, so the token
			// keeps its span.
			name:  "a multi-byte rune before",
			src:   "日本語" + token,
			start: 9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := []Span{{tt.start, tt.start + len(token)}}
			if got, _ := DopplerAuthToken().Find(tt.src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, want)
			}
		})
	}
}

func Test_DopplerAuthToken_leavesWhatFollowsAlone(t *testing.T) {
	// A body is forty-four characters at the widest, so what is written after
	// one stays whatever it is written in.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "sentence",
			src:  "the token is dp.pt.0123456789abcdef0123456789abcdef0123456789a.",
			want: "the token is *************************************************.",
		},
		{
			name: "quoted",
			src:  `"dp.pt.0123456789abcdef0123456789abcdef0123456789a"`,
			want: `"*************************************************"`,
		},
		{
			// A character the alphabet does admit: the cut is what ends a body,
			// so the last character stays in the text rather than joining it.
			name: "a digit written against a token at the widest body",
			src:  "dp.pt.0123456789abcdef0123456789abcdef0123456789abc",
			want: "**************************************************c",
		},
	}

	m := New(WithPatterns(DopplerAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DopplerAuthToken_theSegmentOnlyAServiceTokenCarries(t *testing.T) {
	// The corner builtin_doppler_auth_token.go argues. Doppler gives the
	// optional environment segment to dp.st. and to no other kind, and the two
	// readings of a service token cannot both stand: a segment closes within
	// thirty-five characters and a body opens on forty.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a service token with a segment",
			src:  "dp.st.dev.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 53}},
		},
		{
			name: "a service token with none",
			src:  "dp.st.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 49}},
		},
		{
			name: "a segment carrying the hyphen and the underscore its alphabet adds",
			src:  "dp.st.acme-web_prd.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 62}},
		},
		{
			// The alphabets are what tell a segment from a body, so an uppercase
			// letter is no segment character however short the run is.
			name: "a segment carrying an uppercase letter",
			src:  "dp.st.Dev.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a segment of one character",
			src:  "dp.st.a.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a segment one character wider than the widest",
			src:  "dp.st.0123456789abcdef0123456789abcdef0123.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a segment at the widest there is",
			src:  "dp.st.0123456789abcdef0123456789abcdef012.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 85}},
		},
		{
			// The kinds that carry none: the segment is read as the body it is
			// too short to be, and nothing is located.
			name: "a segment written on a personal token",
			src:  "dp.pt.dev.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a segment written on an audit token",
			src:  "dp.audit.dev.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a segment written on a cli token",
			src:  "dp.ct.dev.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a segment written on a service account token",
			src:  "dp.sa.dev.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a segment written on a service account identity token",
			src:  "dp.said.dev.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			name: "a segment written on a scim token",
			src:  "dp.scim.dev.0123456789abcdef0123456789abcdef0123456789a",
		},
		{
			// The segment's floor: two characters, the shortest a run may be
			// and still close on the separator rather than being read as the
			// opening of a body.
			name: "a segment at the shortest there is",
			src:  "dp.st.qa.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 52}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DopplerAuthToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DopplerAuthToken_theKindNoRulesetReads(t *testing.T) {
	// The service account identity token, which builtin_doppler_auth_token.go
	// argues for reading. Doppler's page prints it beside the other six with a
	// format of its own; trufflehog, noseyparker and kingfisher each read those
	// six and leave this one out, and gitleaks reads the personal token alone.
	//
	// Both cases here are the same body written behind two prefixes that share
	// their first four characters, which is what a scan reading kinds one
	// character at a time would get wrong.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a service account identity token",
			src:  "dp.said.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 51}},
		},
		{
			name: "the service account token whose kind opens it",
			src:  "dp.sa.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 49}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DopplerAuthToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DopplerAuthToken_aSegmentClosingWithTheOpening(t *testing.T) {
	// What advancing rather than consuming the match has to find here, and the
	// answer is nothing. A candidate opens on the two letters and the separator
	// behind them, and inside a token a separator stands only where a kind or a
	// segment closes — so dp. stands inside one exactly where a segment closes
	// with dp. What such a candidate would read as a kind is the body behind
	// that segment, which is forty characters at least where a kind is five at
	// most.
	//
	// So the outer token is located and the candidate inside it is dropped. A
	// scan consuming its match would report the same span here; what the case
	// pins is that the inner candidate is looked at and comes to nothing.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a segment closing with the two letters a prefix opens with",
			src:  "dp.st.mydp.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{0, 54}},
		},
		{
			// And the shape where the inner candidate is the whole of what
			// stands: the outer prefix is followed by a run too short to be
			// either a body or a segment closed by a separator.
			name: "a prefix written in front of another token",
			src:  "dp.st.dp.pt.0123456789abcdef0123456789abcdef0123456789a",
			want: []Span{{6, 55}},
		},
	}

	m := New(WithPatterns(DopplerAuthToken()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DopplerAuthToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Fatalf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
			if got, want := m.Mask(tt.src), tt.src[:tt.want[0].Start]+strings.Repeat("*", tt.want[0].End-tt.want[0].Start); got != want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, want)
			}
		})
	}
}

func Test_DopplerAuthToken_aDigestBehindThePrefix(t *testing.T) {
	// The collision builtin_doppler_auth_token.go pays for rather than ruling
	// out. Forty lowercase hexadecimal characters are a SHA-1 and a body
	// exactly, and sixty-four are a SHA-256 and a run the cut takes a body from,
	// so a prefix and either of them is a token to this scan. Nothing is left in
	// the text to tell the two apart, and a scan declining this would decline
	// every token Doppler issues.
	//
	// What is turned away is the digest with no prefix in front of it, which is
	// what the prefix is for.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a sha-1 behind a prefix",
			src:  "dp.pt.0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 46}},
		},
		{
			name: "a sha-256 behind a prefix",
			src:  "dp.pt.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want: []Span{{0, 50}},
		},
		{
			name: "a sha-1 on its own",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			name: "a sha-256 on its own",
			src:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := DopplerAuthToken().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_DopplerAuthToken_holdsATokenTheInputCutShort(t *testing.T) {
	// What a count read as a range costs a stream, which no span above reports.
	// A body between the two ends of the range is a token where the text ended
	// it and is a token one character shorter than the truth where the end of
	// the input did, so the scan reports the span it has and holds the
	// candidate: the answer is a value found and an offset that says it may yet
	// grow.
	//
	// The two halves are the same text cut and whole. A Writer handed the cut
	// writes nothing out of the token until the rest arrives, and then redacts
	// the whole of it.
	whole := "dp.pt.0123456789abcdef0123456789abcdef0123456789ab"
	cut := whole[:len(whole)-1]

	spans, retain := DopplerAuthToken().Find(cut)
	if want := []Span{{0, len(cut)}}; !slices.Equal(spans, want) {
		t.Errorf("Find(%q) = %v, want %v", cut, spans, want)
	}
	if retain != 0 {
		t.Errorf("Find(%q) settled from %d, want 0", cut, retain)
	}

	m := New(WithPatterns(DopplerAuthToken()))
	var out strings.Builder
	w := NewWriter(&out, m)
	if _, err := w.Write([]byte(cut)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if _, err := w.Write([]byte(whole[len(whole)-1:])); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if got, want := out.String(), strings.Repeat("*", len(whole)); got != want {
		t.Errorf("a token written in two pieces came out %q, want %q", got, want)
	}
}

func Test_DopplerAuthToken_settlesARunWiderThanABody(t *testing.T) {
	// The other side of the same decision, and the reason the cut is settled
	// where a shorter run is not. A run already at the widest a body may be
	// cannot be lengthened into anything else, so a scan handed one at the very
	// end of its input settles the text behind it rather than holding a payload
	// of any length until a stream's limit turns it into asterisks.
	src := "dp.pt." + strings.Repeat("a", 4096)

	spans, retain := DopplerAuthToken().Find(src)
	if want := []Span{{0, 50}}; !slices.Equal(spans, want) {
		t.Errorf("Find(a run of %d) = %v, want %v", 4096, spans, want)
	}
	if retain != len(src) {
		t.Errorf("Find(a run of %d) settled %d of %d, want the whole of it", 4096, retain, len(src))
	}
}

func Test_DopplerAuthToken_scanIsLinear(t *testing.T) {
	// This scan keeps no cursor. What holds it linear is that every walk at a
	// candidate is bounded by a count, and that the one run it reads to the end
	// — the run a body is cut from — begins where a run begins, since the
	// separator in front of it is written in neither alphabet. These are the
	// inputs that would find either of those wrong.
	//
	// The generic guard in builtins_test.go repeats the samples. The crowding a
	// whole line can carry stays here.
	sources := map[string]string{
		// The anchor at every byte, each turned away by the two characters read
		// back from it, which is the cheapest this scan declines anything.
		"the anchor at every byte": strings.Repeat(".", 2000000),
		// A whole prefix every seven characters, each turned away by the space
		// standing where its body would open.
		"a prefix every seven characters": strings.Repeat("dp.pt. ", 280000),
		// A whole prefix every six characters with nothing between them, so
		// every candidate reads the run behind it and none is a body.
		"a prefix every six characters": strings.Repeat("dp.pt.", 330000),
		// One candidate whose body is the whole line. The cut stops it at
		// forty-four characters.
		"a base62 run the length of the line": "dp.pt." + strings.Repeat("a", 2000000),
		// The same run behind the one kind that reads a segment, so the segment
		// walk is offered a run it must not read to the end of.
		"a run behind a service token prefix": "dp.st." + strings.Repeat("a", 2000000),
		// And the run with no prefix in front of it, so no candidate is found in
		// it at all.
		"a base62 run with no prefix": strings.Repeat("a", 2000000),
	}

	checkScanIsLinear(t, DopplerAuthToken(), sources)
}

// Test_dopplerAuthTokenPrefixes holds the prefixes to being what the kinds and
// the two literals around them come to, one prefix a kind.
//
// It is held rather than assumed because the prefixes are what a stream settles
// its tail by, and a prefix missing there is not a token missed but the
// characters of one released: builtin_scan.go says what a table free to
// disagree with the kinds would cost.
func Test_dopplerAuthTokenPrefixes(t *testing.T) {
	// The count builtin_doppler_auth_token.go states in prose, held here so that
	// a kind added fails where the sentence naming the number can be found.
	if got, want := len(dopplerAuthTokenKinds), 7; got != want {
		t.Errorf("the table names %d kind(s) and builtin_doppler_auth_token.go says %d", got, want)
	}
	if got, want := len(dopplerAuthTokenPrefixes), len(dopplerAuthTokenKinds); got != want {
		t.Fatalf("the scan carries %d prefix(es) for %d kind(s)", got, want)
	}
	for i, kind := range dopplerAuthTokenKinds {
		if got, want := dopplerAuthTokenPrefixes[i], "dp."+kind+"."; got != want {
			t.Errorf("the prefix for %q is %q, want %q", kind, got, want)
		}
	}
}

// Test_dopplerAuthTokenAnchor holds the prefixes to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets.
func Test_dopplerAuthTokenAnchor(t *testing.T) {
	for _, prefix := range dopplerAuthTokenPrefixes {
		if dopplerAuthTokenAnchorIndex >= len(prefix) {
			t.Fatalf("the anchor stands at %d, the prefix %q is %d characters", dopplerAuthTokenAnchorIndex, prefix, len(prefix))
		}
		if c := prefix[dopplerAuthTokenAnchorIndex]; c != dopplerAuthTokenAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", prefix, c, byte(dopplerAuthTokenAnchor))
		}
	}

	// What the anchor buys, held rather than claimed in prose: it is written in
	// neither alphabet, so no run of either holds a candidate and no two
	// candidates read one run. Both sentences in
	// builtin_doppler_auth_token.go rest on this — the byte being worth
	// searching for, and the scan needing no cursor.
	if isBase62Byte(dopplerAuthTokenAnchor) {
		t.Errorf("the anchor %q is written in the body's alphabet, so a run of it holds a candidate at every character", byte(dopplerAuthTokenAnchor))
	}
	if isDopplerAuthTokenSegmentByte(dopplerAuthTokenAnchor) {
		t.Errorf("the anchor %q is written in a segment's alphabet, so a segment holds a candidate at every character", byte(dopplerAuthTokenAnchor))
	}
}

// Test_dopplerAuthTokenKindChars holds the width the kind walk is bounded by to
// the longest kind there is.
//
// The walk stops a character past this, so a bound that fell short of a kind
// would locate none of the tokens written with it and a bound that ran past one
// would open candidates on runs no kind can be. Neither is anything the cases
// above report for a kind added later.
func Test_dopplerAuthTokenKindChars(t *testing.T) {
	for _, kind := range dopplerAuthTokenKinds {
		if len(kind) > dopplerAuthTokenKindChars {
			t.Errorf("the kind %q is %d characters, the walk is bounded at %d", kind, len(kind), dopplerAuthTokenKindChars)
		}
	}
	if !slices.ContainsFunc(dopplerAuthTokenKinds, func(kind string) bool { return len(kind) == dopplerAuthTokenKindChars }) {
		t.Errorf("the walk is bounded at %d, which no kind is that wide", dopplerAuthTokenKindChars)
	}
}

// Test_dopplerAuthTokenChars holds the four counts to what Doppler's own
// expressions ask for. What would go wrong without this is the documentation on
// DopplerAuthToken promising those widths, and the spans every case in this file
// is written with.
func Test_dopplerAuthTokenChars(t *testing.T) {
	if got := dopplerAuthTokenBodyMinChars; got != 40 {
		t.Errorf("dopplerAuthTokenBodyMinChars = %d, want the 40 Doppler states", got)
	}
	if got := dopplerAuthTokenBodyMaxChars; got != 44 {
		t.Errorf("dopplerAuthTokenBodyMaxChars = %d, want the 44 Doppler states", got)
	}
	if got := dopplerAuthTokenSegmentMinChars; got != 2 {
		t.Errorf("dopplerAuthTokenSegmentMinChars = %d, want the 2 Doppler states", got)
	}
	if got := dopplerAuthTokenSegmentMaxChars; got != 35 {
		t.Errorf("dopplerAuthTokenSegmentMaxChars = %d, want the 35 Doppler states", got)
	}
}

func Test_isDopplerAuthTokenKind(t *testing.T) {
	// The seven kinds Doppler names a format for, and nothing else. The last
	// three are what a walk reading a kind one character at a time gets wrong:
	// two of them open one of the seven and the third is one of the seven with a
	// character taken off.
	for _, kind := range dopplerAuthTokenKinds {
		if !isDopplerAuthTokenKind(kind) {
			t.Errorf("isDopplerAuthTokenKind(%q) = false, want a kind of the table to be one", kind)
		}
	}
	for _, s := range []string{"", "xx", "CT", "sai", "saidx", "audi"} {
		if isDopplerAuthTokenKind(s) {
			t.Errorf("isDopplerAuthTokenKind(%q) = true, want only the kinds Doppler names", s)
		}
	}
}

func Test_isDopplerAuthTokenSegmentByte(t *testing.T) {
	// The alphabet a Doppler config name is written in, stated over every byte
	// rather than by example: lowercase letters, digits, the hyphen and the
	// underscore. The case is what separates it from the body's alphabet.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'a' <= b && b <= 'z' || b == '-' || b == '_'
		if got := isDopplerAuthTokenSegmentByte(b); got != want {
			t.Errorf("isDopplerAuthTokenSegmentByte(%q) = %v, want %v", b, got, want)
		}
	}
}

// referenceDopplerAuthToken is the expression the scan in
// builtin_doppler_auth_token.go reads by hand: the seven expressions Doppler's
// Auth Token Formats page prints, written as one alternation so that the scan
// can be held to them.
//
// Every kind, both counts and both character classes are spelled again rather
// than built from the declarations beside the scan. A reference sharing those
// could not disagree with the scan about them, and it is exactly that
// disagreement the fuzz target below is for.
//
// The branches are written in the order the vendor's page lists them, which is
// the order an engine tries them in. Nothing rests on it: no kind is a prefix of
// another with a separator where the shorter one would need it, so at most one
// branch can match at a given position however they are ordered.
//
// Both repetitions are bounded, so the machine an engine builds for a candidate
// is read once and stops, where a floor spelled as a counted repetition would
// cost a machine as wide as the floor at every candidate. What an engine
// searches the text for is the three character literal every branch opens with,
// of which the last is written in neither of the two alphabets — so no run of
// either is a place the search stops.
var referenceDopplerAuthToken = regexp.MustCompile(`dp\.ct\.[0-9A-Za-z]{40,44}` +
	`|dp\.pt\.[0-9A-Za-z]{40,44}` +
	`|dp\.st\.(?:[0-9a-z_-]{2,35}\.)?[0-9A-Za-z]{40,44}` +
	`|dp\.sa\.[0-9A-Za-z]{40,44}` +
	`|dp\.said\.[0-9A-Za-z]{40,44}` +
	`|dp\.scim\.[0-9A-Za-z]{40,44}` +
	`|dp\.audit\.[0-9A-Za-z]{40,44}`)

// referenceDopplerAuthTokenFind locates tokens the plain way: the leftmost match
// of the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does.
// Here it finds nothing the scan does not — a token can hold the opening only
// inside a segment, where the kind behind it is a body — and it is kept because
// a reference is written to know nothing its scan claims.
func referenceDopplerAuthTokenFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceDopplerAuthToken.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzDopplerAuthToken_matchesReference guards the hand-written scan: the
// opening it searches for, the kinds it reads behind it, the kind it lets carry
// an environment segment, both counts, both alphabets and the byte it resumes at
// may none of them change which tokens are located.
func FuzzDopplerAuthToken_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("DOPPLER_TOKEN=dp.pt.0123456789abcdef0123456789abcdef0123456789a")
	// One of each kind, in the order the vendor's page lists them.
	f.Add("dp.ct.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.pt.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.st.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.st.dev.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.sa.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.said.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.scim.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.audit.0123456789abcdef0123456789abcdef0123456789a")
	// Both ends of the count, and either side of them.
	f.Add("dp.pt.0123456789abcdef0123456789abcdef0123456")      // one short of the shortest
	f.Add("dp.pt.0123456789abcdef0123456789abcdef01234567")     // the shortest
	f.Add("dp.pt.0123456789abcdef0123456789abcdef0123456789ab") // the widest
	f.Add("dp.pt.0123456789abcdef0123456789abcdef0123456789abc")
	f.Add("dp.pt." + strings.Repeat("a", 128))
	// The alphabet a body is read in, and the characters it turns away.
	f.Add("dp.pt.0123456789ABCDEF0123456789ABCDEF0123456789A")
	f.Add("dp.pt.0123456789abcdef-123456789abcdef0123456789a")
	f.Add("dp.pt.0123456789abcdef_123456789abcdef0123456789a")
	f.Add("dp.pt.0123456789abcdef.123456789abcdef0123456789a")
	f.Add("dp.pt.0123456789abcdef 123456789abcdef0123456789a")
	f.Add("dp.pt.0123456789abcdef\n123456789abcdef0123456789a")
	// The segment: on the kind that carries one, on a kind that does not, at
	// each end of its width and written in a character its alphabet declines.
	f.Add("dp.st.acme-web_prd.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.pt.dev.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.st.a.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.st.ab.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.st.Dev.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.st.0123456789abcdef0123456789abcdef012.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.st.0123456789abcdef0123456789abcdef0123.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.st." + strings.Repeat("a", 64) + ".0123456789abcdef0123456789abcdef0123456789a")
	// The kinds and the openings that are not.
	f.Add("dp.xx.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp..0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.pt0123456789abcdef0123456789abcdef0123456789a")
	f.Add("DP.PT.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dppt.0123456789abcdef0123456789abcdef0123456789a")
	// A prefix inside a token, two tokens together, and candidate positions
	// crowded as close as they can be.
	f.Add("dp.st.mydp.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.st.dp.pt.0123456789abcdef0123456789abcdef0123456789a")
	f.Add("dp.pt.0123456789abcdef0123456789abcdef0123456789adp.audit.0123456789abcdef0123456789abcdef0123456789a")
	f.Add(strings.Repeat("dp.pt.", 64))
	f.Add(strings.Repeat("dp.pt. ", 64))
	f.Add(strings.Repeat("dp.st.", 64))
	f.Add(strings.Repeat(".", 128))
	f.Add(strings.Repeat("dp.pt.0123456789abcdef0123456789abcdef0123456789a", 4))
	f.Add(`time=2026-08-17T00:00:00Z level=info msg="fetching secrets" project=acme-api config=prd url=https://api.doppler.com/v3/configs`)

	fuzzAgainstReference(f, DopplerAuthToken().Find, referenceDopplerAuthTokenFind)
}

// dopplerAuthTokenFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func dopplerAuthTokenFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against, and it is the vendor's own host
	// name and API path — which is where the two letters of the opening are
	// commonest. The full stop stands twice on it against the d's four and the
	// p's seven, and every stop is answered by the two characters read back from
	// it.
	line := `time=2026-08-17T00:00:00Z level=info msg="fetching secrets" project=acme-api config=prd url=https://api.doppler.com/v3/configs/config/secrets/download `
	token := "dp.pt.0123456789abcdef0123456789abcdef0123456789a"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A whole prefix every seven characters, each turned away by the
			// space standing where its body would open — which is the cheapest
			// this scan declines a candidate once the kind has been read.
			name:  "candidates that are not values",
			src:   strings.Repeat("dp.pt. ", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads an opening, since what stands in front of
			// each is the anchor rather than the two letters. That is two
			// comparisons a stop, and the cheapest a stop is answered for at
			// all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat(".", 4096),
			spans: 0,
		},
		{
			// The way a candidate is walked furthest without becoming a value: a
			// body one character short of the shortest, so the whole of it is
			// read before the count turns it away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("dp.pt.0123456789abcdef0123456789abcdef0123456 ", 16),
			spans: 0,
		},
		{
			// And the same for the one kind that reads a segment, where the walk
			// is offered a run wider than any segment and must stop inside it.
			name:  "segments turned away by their width",
			src:   strings.Repeat("dp.st."+strings.Repeat("a", 36)+". ", 16),
			spans: 0,
		},
		{
			// A base62 run carrying no character of the opening at all, which is
			// what a digest and an identifier are written in, so the search walks
			// the whole of it in one pass.
			name:  "a run of the body alphabet",
			src:   strings.Repeat("0123456789abcdef", 256),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "token=" + token,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "token=" + token,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"token="+token+"\n", 32),
			spans: 32,
		},
		{
			// The longest path a value is read by: the kind, then a segment,
			// then the body behind it.
			name:  "many service tokens carrying a segment",
			src:   strings.Repeat(line+"token=dp.st.dev.0123456789abcdef0123456789abcdef0123456789a\n", 32),
			spans: 32,
		},
	}
}
