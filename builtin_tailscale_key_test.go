package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Tailscale key pattern: what it locates and what it leaves alone, written
// out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. Each half is built from the run
// 0123456789abcdef separately, twelve characters for the identifier and sixteen
// for the secret. Neither is a count the pattern reads — it reads none — so
// those two widths are for readability alone, a half written to any other
// length is a half just the same, and the cases that turn on the length say so.
// The halves are spelled in lowercase where the case does not matter and in
// uppercase where the case is what a case is about: both are written in the
// letters of either case and the digits, so either spelling is a half.

func Test_TailscaleKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an auth key on its own",
			src:  "tskey-auth-0123456789ab-0123456789abcdef",
			want: []Span{{0, 40}},
		},
		{
			name: "an auth key in an environment assignment",
			src:  "TS_AUTHKEY=tskey-auth-0123456789ab-0123456789abcdef",
			want: []Span{{11, 51}},
		},
		{
			name: "an api access token",
			src:  "tskey-api-0123456789ab-0123456789abcdef",
			want: []Span{{0, 39}},
		},
		{
			name: "an oauth client key",
			src:  "tskey-client-0123456789ab-0123456789abcdef",
			want: []Span{{0, 42}},
		},
		{
			name: "a scim key",
			src:  "tskey-scim-0123456789ab-0123456789abcdef",
			want: []Span{{0, 40}},
		},
		{
			name: "a webhook key",
			src:  "tskey-webhook-0123456789ab-0123456789abcdef",
			want: []Span{{0, 43}},
		},
		{
			// Both halves are written in the letters of either case and the
			// digits, so capitals are a half.
			name: "halves written in capitals",
			src:  "tskey-auth-0123456789AB-0123456789ABCDEF",
			want: []Span{{0, 40}},
		},
		{
			// The ordered run the cases above are built from reaches j in the
			// identifier and f in the secret, so the letters past those two
			// stand in no case that run wrote. Here they stand in both halves,
			// at the first character of each and at the last: a scan reading
			// the halves as hexadecimal, or as the lower half of the alphabet,
			// passes every other case in this file and fails this one.
			name: "the letters the ordered run never reaches",
			src:  "tskey-auth-ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ-ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ",
			want: []Span{{0, 92}},
		},
		{
			// The pattern reads no count for either half, so a key of one
			// character a side is a key.
			name: "one character in each half",
			src:  "tskey-auth-0-1",
			want: []Span{{0, 14}},
		},
		{
			// And a half far longer than anything Tailscale writes is read to
			// the end of its run rather than cut to a length.
			name: "halves longer than the ones tailscale writes",
			src:  "tskey-auth-0123456789abcdefghij-0123456789abcdefghijklmnopqrstuvwxyz",
			want: []Span{{0, 68}},
		},
		{
			name: "two keys separated by a space",
			src:  "tskey-auth-0123456789ab-0123456789abcdef tskey-api-0123456789AB-0123456789ABCDEF",
			want: []Span{{0, 40}, {41, 80}},
		},
		{
			// The opening is written in the letters a half is written with and
			// the separator that divides them, so a key can begin inside the
			// one before it: the first key's identifier is tskey and its secret
			// auth, and the second begins ten characters into it. A scan
			// resuming past a match would step over it. The spans overlap,
			// which a Masker resolves into one.
			name: "a key beginning inside the key before it",
			src:  "tskey-api-tskey-auth-0-1",
			want: []Span{{0, 20}, {10, 24}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := TailscaleKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TailscaleKey_wrappedForTailnetLock(t *testing.T) {
	// The shape TailnetLockWrapPreauthKey writes: an auth key, the literal
	// --TL, a credential signature and the wrapping private key, the last two
	// in standard base64 with a hyphen between them. The whole of it is one
	// span, because reading the key alone would leave a signing private key in
	// the text behind a redaction that reads as if the credential had been
	// dealt with.
	//
	// The cases below the first two are the ways a suffix is not one. Each
	// leaves the key located and the text behind it alone, which is what says
	// the suffix is read as its own grammar rather than as "whatever follows".
	key := "tskey-auth-0123456789ab-0123456789abcdef"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a wrapped auth key",
			src:  key + "--TL0123456789abcdef-0123456789abcdefghij",
			want: []Span{{0, 81}},
		},
		{
			// The two characters standard base64 writes where base64url writes
			// a hyphen and an underscore. Both belong to a suffix, and neither
			// belongs to the key in front of it.
			name: "a suffix carrying the characters standard base64 adds",
			src:  key + "--TL0123456789ab+/ef-0123456789abcdefghij",
			want: []Span{{0, 81}},
		},
		{
			name: "a suffix with no separator between its halves",
			src:  key + "--TL0123456789abcdef",
			want: []Span{{0, 40}},
		},
		{
			name: "a suffix whose signature is of no characters",
			src:  key + "--TL-0123456789abcdefghij",
			want: []Span{{0, 40}},
		},
		{
			name: "a suffix whose private key is of no characters",
			src:  key + "--TL0123456789abcdef- and prose",
			want: []Span{{0, 40}},
		},
		{
			// The literal is read in the case Tailscale writes it.
			name: "a lowercase letter in the wrapping literal",
			src:  key + "--Tl0123456789abcdef-0123456789abcdefghij",
			want: []Span{{0, 40}},
		},
		{
			name: "one hyphen where the wrapping literal carries two",
			src:  key + "-TL0123456789abcdef-0123456789abcdefghij",
			want: []Span{{0, 40}},
		},
		{
			// The underscore is a base64url character and no standard base64
			// one, so it ends the run it stands in: in the signature it leaves
			// no separator where one is wanted and the suffix is not read at
			// all, in the private key it simply ends the suffix.
			name: "an underscore inside the signature",
			src:  key + "--TL0123456789_abcdef-0123456789abcdefghij",
			want: []Span{{0, 40}},
		},
		{
			name: "an underscore inside the private key",
			src:  key + "--TL0123456789abcdef-0123456789_abcdefghij",
			want: []Span{{0, 71}},
		},
		{
			// RawStdEncoding writes no padding, so the padding character is
			// outside the alphabet and closes the private key's run.
			name: "padding written after the private key",
			src:  key + "--TL0123456789abcdef-0123456789abcdefghij==",
			want: []Span{{0, 81}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := TailscaleKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TailscaleKey_wrappingBehindEveryKind(t *testing.T) {
	// The suffix is read behind a key of any kind, which is wider than what
	// Tailscale writes: only a pre-auth key is ever wrapped. None of the
	// strings below the first is one Tailscale produced, and each is redacted
	// whole anyway. builtin_tailscale_key.go weighs that widening against
	// gating on the kind; the cases are here so that a reader changing the scan
	// meets the decision rather than the behaviour.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "behind an auth key, which is the kind tailscale wraps",
			src:  "tskey-auth-a-b--TLxy-z",
			want: []Span{{0, 22}},
		},
		{
			name: "behind an api access token",
			src:  "tskey-api-a-b--TLxy-z",
			want: []Span{{0, 21}},
		},
		{
			name: "behind an oauth client key",
			src:  "tskey-client-a-b--TLxy-z",
			want: []Span{{0, 24}},
		},
		{
			name: "behind a scim key",
			src:  "tskey-scim-a-b--TLxy-z",
			want: []Span{{0, 22}},
		},
		{
			name: "behind a webhook key",
			src:  "tskey-webhook-a-b--TLxy-z",
			want: []Span{{0, 25}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := TailscaleKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TailscaleKey_wrappedSuffixReachesTheEndOfItsRun(t *testing.T) {
	// The one place this pattern over-redacts on account of its second
	// alphabet, held to the answer it gives rather than to the one a reader
	// might want. Standard base64 admits the solidus where base62 does not, so
	// the private key's run walks straight through a path separator and the
	// segments behind a wrapped key go with it.
	//
	// builtin_tailscale_key.go weighs reading the ed25519 count against this and
	// declines it. The second case is what stops the run wherever a character
	// outside standard base64 stands, which is what an ordinary log line, a
	// quote and a shell all write.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a wrapped key written into a path",
			src:  "tskey-auth-0123456789ab-0123456789abcdef--TL0123456789abcdef-0123456789abcdefghij/next/segment",
			want: strings.Repeat("*", 94),
		},
		{
			name: "a character outside standard base64 against the private key",
			src:  "tskey-auth-0123456789ab-0123456789abcdef--TL0123456789abcdef-0123456789abcdefghij?next",
			want: strings.Repeat("*", 81) + "?next",
		},
	}

	m := New(WithPatterns(TailscaleKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TailscaleKey_wrappedKeyIsRedactedWhole(t *testing.T) {
	// The point of reading the suffix, stated where a reader sees the output:
	// nothing of the signature or the wrapping private key survives the
	// redaction. Were the key alone located, everything from --TL on would
	// stand in the text.
	src := "tailscale up --authkey tskey-auth-0123456789ab-0123456789abcdef--TL0123456789abcdef-0123456789abcdefghij"
	want := "tailscale up --authkey " + strings.Repeat("*", 81)

	m := New(WithPatterns(TailscaleKey()))
	if got := m.Mask(src); got != want {
		t.Errorf("Mask(%q) = %q, want %q", src, got, want)
	}
}

func Test_TailscaleKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "tskey-auth-",
		},
		{
			// The separator dividing the identifier from the secret has not
			// been written, so there is no secret to locate.
			name: "an identifier with no separator behind it",
			src:  "tskey-auth-0123456789ab",
		},
		{
			name: "a separator with no secret behind it",
			src:  "tskey-auth-0123456789ab-",
		},
		{
			// The identifier and the secret each hold at least one character.
			// A half of none is written where the separator stands directly
			// against the one in front of it.
			name: "an identifier of no characters",
			src:  "tskey-auth--0123456789abcdef",
		},
		{
			name: "a secret of no characters",
			src:  "tskey-auth-0123456789ab--0123456789abcdef",
		},
		{
			// The underscore is no character either half is written with, so it
			// ends the run it stands in — at the first character of a half, at
			// its last and in the middle alike.
			name: "an underscore at the first character of the identifier",
			src:  "tskey-auth-_0123456789ab-0123456789abcdef",
		},
		{
			name: "an underscore at the last character of the identifier",
			src:  "tskey-auth-0123456789ab_-0123456789abcdef",
		},
		{
			name: "an underscore inside the identifier",
			src:  "tskey-auth-0123456789_ab-0123456789abcdef",
		},
		{
			name: "an underscore at the first character of the secret",
			src:  "tskey-auth-0123456789ab-_0123456789abcdef",
		},
		{
			// The six bytes standing just outside the three ranges a half is
			// written in, three of them at the first character of an identifier
			// and three at its last. An excluded character written anywhere
			// else in this file is a space, a dot or an underscore, none of
			// which is adjacent to a range, so a range test off by one is
			// invisible without these.
			name: "the byte below the digits at the first character of the identifier",
			src:  "tskey-auth-/0123456789ab-0123456789abcdef",
		},
		{
			name: "the byte above the digits at the last character of the identifier",
			src:  "tskey-auth-0123456789ab:-0123456789abcdef",
		},
		{
			name: "the byte below the capitals at the first character of the identifier",
			src:  "tskey-auth-@0123456789ab-0123456789abcdef",
		},
		{
			name: "the byte above the capitals at the last character of the identifier",
			src:  "tskey-auth-0123456789ab[-0123456789abcdef",
		},
		{
			name: "the byte below the lowercase letters at the first character of the identifier",
			src:  "tskey-auth-`0123456789ab-0123456789abcdef",
		},
		{
			name: "the byte above the lowercase letters at the last character of the identifier",
			src:  "tskey-auth-0123456789ab{-0123456789abcdef",
		},
		{
			// The anchor stands two characters into the opening and a candidate
			// is read back from it, so a text whose first anchor stands closer
			// to the start than that is where the read-back would reach in
			// front of the input.
			name: "the opening cut to its anchor",
			src:  "key-auth-0123456789ab-0123456789abcdef",
		},
		{
			name: "the opening cut to one character in front of its anchor",
			src:  "skey-auth-0123456789ab-0123456789abcdef",
		},
		{
			name: "a space inside the identifier",
			src:  "tskey-auth-0123456789 ab-0123456789abcdef",
		},
		{
			name: "a dot inside the identifier",
			src:  "tskey-auth-0123456789.ab-0123456789abcdef",
		},
		{
			name: "an identifier broken by a line break",
			src:  "tskey-auth-0123456789\nab-0123456789abcdef",
		},
		{
			// The kinds are the five Tailscale documents, written in the case
			// it documents them in.
			name: "a kind tailscale does not write",
			src:  "tskey-oauth-0123456789ab-0123456789abcdef",
		},
		{
			name: "a kind with a character written after it",
			src:  "tskey-authx-0123456789ab-0123456789abcdef",
		},
		{
			name: "an uppercase kind",
			src:  "tskey-AUTH-0123456789ab-0123456789abcdef",
		},
		{
			name: "no kind at all",
			src:  "tskey-0123456789ab-0123456789abcdef",
		},
		{
			name: "an uppercase opening",
			src:  "TSKEY-auth-0123456789ab-0123456789abcdef",
		},
		{
			name: "one character of the opening wrong",
			src:  "tskcy-auth-0123456789ab-0123456789abcdef",
		},
		{
			// The opening closes with the separator, and the separator divides
			// the halves. Underscores in their place open no candidate at all.
			name: "underscores where the separators stand",
			src:  "tskey_auth_0123456789ab_0123456789abcdef",
		},
		{
			// The key shape the auth keys page still writes: the opening and a
			// run, with no kind and no second half. It is not read, and
			// builtin_tailscale_key.go says why.
			name: "the shape tailscale documented before it prefixed by kind",
			src:  "tskey-0123456789abcdef",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
		{
			// A hostname of a tailnet, which is where the letters of the
			// opening are written in ordinary text.
			name: "a tailscale hostname",
			src:  "https://login.tailscale.com/machine/register",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := TailscaleKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_TailscaleKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "TS_AUTHKEY=tskey-auth-0123456789ab-0123456789abcdef",
			want: "TS_AUTHKEY=****************************************",
		},
		{
			// The flag the client joins a tailnet with.
			name: "a command line",
			src:  "tailscale up --authkey tskey-auth-0123456789ab-0123456789abcdef",
			want: "tailscale up --authkey ****************************************",
		},
		{
			name: "json",
			src:  `{"authKey":"tskey-auth-0123456789ab-0123456789abcdef"}`,
			want: `{"authKey":"****************************************"}`,
		},
		{
			// The header a request to the API carries an access token in.
			name: "an authorization header",
			src:  "Authorization: Bearer tskey-api-0123456789ab-0123456789abcdef",
			want: "Authorization: Bearer ***************************************",
		},
		{
			// And the other way the API takes one: as the user half of basic
			// authentication, with the password left blank.
			name: "a curl command using basic authentication",
			src:  `curl -u "tskey-api-0123456789ab-0123456789abcdef:" https://api.tailscale.com/api/v2/tailnet/-/devices`,
			want: `curl -u "***************************************:" https://api.tailscale.com/api/v2/tailnet/-/devices`,
		},
		{
			name: "a kubernetes secret",
			src:  "  TS_AUTHKEY: tskey-auth-0123456789ab-0123456789abcdef",
			want: "  TS_AUTHKEY: ****************************************",
		},
		{
			name: "twice",
			src:  "tskey-auth-0123456789ab-0123456789abcdef tskey-api-0123456789AB-0123456789ABCDEF",
			want: "**************************************** ***************************************",
		},
		{
			// The two spans are merged, so the key that begins inside the one
			// before it leaves nothing of itself behind.
			name: "a key beginning inside the key before it",
			src:  "tskey-api-tskey-auth-0-1",
			want: "************************",
		},
	}

	m := New(WithPatterns(TailscaleKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TailscaleKey_nextToWordCharacters(t *testing.T) {
	// A word boundary in front of the pattern would not trim these matches but
	// drop them, letting the key through whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "word character before",
			src:  "xtskey-auth-0123456789ab-0123456789abcdef",
			want: "x****************************************",
		},
		{
			name: "underscore before",
			src:  "TS_AUTHKEY_tskey-auth-0123456789ab-0123456789abcdef",
			want: "TS_AUTHKEY_****************************************",
		},
	}

	m := New(WithPatterns(TailscaleKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TailscaleKey_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading no count. Where a key ends is where the run its
	// secret stands in stops, so a letter or a digit written straight against a
	// key is redacted with it — which is what buys a key of a length Tailscale
	// states nowhere being located whole. The run is the letters of either case
	// and the digits, so a hyphen, an underscore or anything outside them ends
	// a key where it stands.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is tskey-auth-0123456789ab-0123456789abcdef.",
			want: "the key is ****************************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export TS_AUTHKEY="tskey-auth-0123456789ab-0123456789abcdef"`,
			want: `export TS_AUTHKEY="****************************************"`,
		},
		{
			name: "a word against the key",
			src:  "tskey-auth-0123456789ab-0123456789abcdefsuffix",
			want: "**********************************************",
		},
		{
			name: "a dashed word against the key",
			src:  "tskey-auth-0123456789ab-0123456789abcdef-suffix",
			want: "****************************************-suffix",
		},
		{
			name: "an underscored word against the key",
			src:  "tskey-auth-0123456789ab-0123456789abcdef_suffix",
			want: "****************************************_suffix",
		},
		{
			// An underscore inside the secret ends it there, so what is
			// redacted is the key up to the underscore and the rest is left.
			name: "an underscore inside the secret",
			src:  "tskey-auth-0123456789ab-0123456789_abcdef",
			want: "**********************************_abcdef",
		},
		{
			// The byte standing just above the lowercase letters, closing the
			// secret's run where the cases above close it with characters far
			// from a range's end.
			name: "the byte above the lowercase letters against the secret",
			src:  "tskey-auth-0123456789ab-0123456789abcdef{",
			want: "****************************************{",
		},
	}

	m := New(WithPatterns(TailscaleKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TailscaleKey_shortestShape(t *testing.T) {
	// What this pattern redacts that nobody issued, held to being redacted
	// rather than to being spared. Tailscale states no length for either half,
	// so a prefix and one character a side is a key's format exactly and
	// nothing is left in the text to tell the two apart: a pattern letting
	// these through would let a real key of the same shape through with it.
	//
	// What is taken is opaque to a reader either way — ten characters of prefix
	// at the shortest and two runs with a hyphen between them is not text
	// somebody wrote. The cases move with the scan, so a floor raised later shows up
	// here as a decision rather than as something the next reader discovers.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "one character in each half",
			src:  "tskey-auth-x-y",
			want: "**************",
		},
		{
			name: "the shortest prefix and one character in each half",
			src:  "tskey-api-x-y",
			want: "*************",
		},
	}

	m := New(WithPatterns(TailscaleKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_TailscaleKey_holdsAKeyTheInputCutShort(t *testing.T) {
	// What a scan settles for a candidate the end of the input cut short:
	// nothing behind that candidate's own start, and nothing in front of it
	// either. The secret is read to the end of its run, so a run reaching the
	// end of the input may still be carried on by what arrives next, and the
	// key already located there may still grow.
	whole := "see tskey-auth-0123456789ab-0123456789abcdef"
	cut := whole[:len(whole)-1]

	spans, retain := TailscaleKey().Find(cut)
	if want := []Span{{4, len(cut)}}; !slices.Equal(spans, want) {
		t.Errorf("Find(%q) = %v, want %v", cut, spans, want)
	}
	if want := 4; retain != want {
		t.Errorf("Find(%q) settled from %d, want %d", cut, retain, want)
	}

	spans, retain = TailscaleKey().Find(whole)
	if want := []Span{{4, len(whole)}}; !slices.Equal(spans, want) {
		t.Errorf("Find(%q) = %v, want %v", whole, spans, want)
	}
	if want := 4; retain != want {
		t.Errorf("Find(%q) settled from %d, want %d", whole, retain, want)
	}

	// The identifier reaching the end of the input is the other half of it: the
	// separator that would divide it from a secret has not arrived, so nothing
	// is located and the candidate is held from its own start.
	half := "see tskey-auth-0123456789ab"
	spans, retain = TailscaleKey().Find(half)
	if len(spans) != 0 {
		t.Errorf("Find(%q) = %v, want no span", half, spans)
	}
	if want := 4; retain != want {
		t.Errorf("Find(%q) settled from %d, want %d", half, retain, want)
	}

	m := New(WithPatterns(TailscaleKey()))
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
	if got, want := out.String(), "see "+strings.Repeat("*", len(whole)-4); got != want {
		t.Errorf("a key written in two pieces came out %q, want %q", got, want)
	}
}

// Test_tailscaleKeyAnchor holds every prefix to carrying the byte the scan
// searches the input for at the index it reads a candidate back from.
// builtin_scan.go says why that is held here rather than left to the targets:
// a kind added to tailscaleKeyKinds whose prefix does not carry the anchor
// there would be located nowhere, and nothing else would report it.
func Test_tailscaleKeyAnchor(t *testing.T) {
	if len(tailscaleKeyPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}
	for _, p := range tailscaleKeyPrefixes {
		if tailscaleKeyAnchorIndex >= len(p) {
			t.Errorf("the anchor stands at %d, the prefix %q is %d characters", tailscaleKeyAnchorIndex, p, len(p))
			continue
		}
		if c := p[tailscaleKeyAnchorIndex]; c != tailscaleKeyAnchor {
			t.Errorf("the prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it", p, c, byte(tailscaleKeyAnchor))
		}
	}
}

func Test_tailscaleKeySeparator_runsDoNotOverlap(t *testing.T) {
	// The scan walks the two runs behind every candidate and keeps no cursor
	// over either. What makes the cursor unnecessary is that a run is read as
	// an identifier by one candidate at most and as a secret by one candidate
	// at most, so no run of the input is walked more than twice however densely
	// the candidates are crowded. That rests on the separator belonging to
	// neither half: a run is then the maximal one at the byte it begins, and
	// where it begins is fixed by the separator in front of it. Were the
	// separator a character a half admits, a run dense in prefixes would be
	// walked once for every candidate in it and the scan would cost time
	// quadratic in the length of such a line.
	if isBase62Byte(tailscaleKeySeparator) {
		t.Errorf("the separator is %q, which a half may be written with, so two candidates can read the same run", byte(tailscaleKeySeparator))
	}
	for _, p := range tailscaleKeyPrefixes {
		if c := p[len(p)-1]; c != tailscaleKeySeparator {
			t.Errorf("the prefix %q closes with %q rather than the separator, so the run behind it does not begin where the argument says", p, c)
		}
	}
}

func Test_TailscaleKey_scanIsLinear(t *testing.T) {
	// Rejecting a candidate resumes one byte along, so a line dense in prefixes
	// holds a candidate for every ten characters it has. What a candidate reads
	// that is a walk over the rest of the input rather than a bounded test is
	// where its two runs end, and repeating those walks at every candidate
	// would cost time quadratic in the length of the line. The bound here is
	// far above a linear scan and far below a quadratic one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every forty bytes where they are densest, because a sample has
	// to carry a whole key to be one. The crowding a line can actually carry
	// stays here.
	sources := map[string]string{
		// Candidates as close together as a prefix allows, none of them with an
		// identifier at all: every one reaches the body of the loop and every
		// one is rejected.
		"a candidate every twelve characters": strings.Repeat("tskey-auth-.", 150000),
		// Keys written into one another, each beginning ten characters into the
		// one in front of it, so every candidate is a key and every one of them
		// walks two runs.
		"a key beginning inside every key": strings.Repeat("tskey-api-", 200000) + "0-1",
		// One candidate whose identifier is the whole line, which is the walk
		// over a run reading the length of the input and finding nothing.
		"an identifier that runs the length of the line": "tskey-auth-" + strings.Repeat("a", 1800000),
		// And one whose secret is, which is the same walk finding a key.
		"a secret that runs the length of the line": "tskey-auth-0-" + strings.Repeat("a", 1800000),
		// An anchor every other byte with nothing in front of it that opens the
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("ak", 900000),
		// And the letters of the opening with no anchor among them, which is
		// the walk reading a whole line and stopping nowhere in it.
		"the letters of the opening with no anchor": strings.Repeat("tsey-", 400000),
		// A wrapping suffix whose signature is the whole line: one candidate
		// walking a base64 run the length of the input and finding no hyphen
		// to end it.
		"a wrapping signature that runs the length of the line": "tskey-auth-0-1--TL" + strings.Repeat("a", 1800000),
		// Crowded candidates that reach the suffix walk and are turned away by
		// it: the underscore is outside standard base64, so the signature run
		// is empty and no suffix is found.
		"a candidate every nineteen characters turned away by the suffix walk": strings.Repeat("tskey-auth-0-1--TL_", 100000),
		// And crowded candidates that each find one. Every unit's suffix is
		// read out of the unit behind it — the next tskey is the signature and
		// its auth the private key — so every candidate walks four runs rather
		// than two, and each span reaches into the unit after it.
		"a wrapping suffix on every candidate": strings.Repeat("tskey-auth-0-1--TL", 100000),
	}

	checkScanIsLinear(t, TailscaleKey(), sources)
}

// referenceTailscaleKey is the expression the scan in builtin_tailscale_key.go
// reads by hand: the statement of what a Tailscale key is, kept here so that
// the scan can be held to it.
//
// The opening, the kinds, the separators, the wrapping literal and both
// alphabets are spelled again rather than built from tailscaleKeyOpening,
// tailscaleKeyKinds, tailscaleKeySeparator, tailscaleKeyWrapOpening,
// isBase62Byte and isTailscaleKeyWrapByte. A reference sharing those
// declarations could not disagree with the scan about them, and it is exactly
// that disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
//
// Every half is written as a plain repetition rather than as a counted one,
// which is what keeps an engine from building a machine as wide as a floor at
// every candidate. There is nothing here for a floor to be built from: the
// pattern reads no count for any of the four.
//
// The wrapping suffix is optional and greedy, which is the scan's own order
// written as an expression: the secret is read to the end of its run first, and
// only a whole key is looked at for a suffix. The two cannot disagree about
// where the secret stops, since the hyphen the suffix opens with is no
// character a secret is written with.
var referenceTailscaleKey = regexp.MustCompile(
	`tskey-(?:api|auth|client|scim|webhook)-[0-9A-Za-z]+-[0-9A-Za-z]+(?:--TL[0-9A-Za-z+/]+-[0-9A-Za-z+/]+)?`,
)

// referenceTailscaleKeyFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the opening is
// written in the letters the halves are and closes with the separator that
// divides them, so a key's own halves can spell the opening of the next. The
// scan finds both and reports the two spans overlapping for a Masker to
// resolve, so the reference must ask about both.
func referenceTailscaleKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceTailscaleKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzTailscaleKey_matchesReference guards the hand-written scan: the opening
// it searches for, the kinds it reads behind that opening, the separators it
// asks for, the alphabet it reads the two halves in and the byte it resumes at
// may none of them change which keys are located.
func FuzzTailscaleKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("TS_AUTHKEY=tskey-auth-0123456789ab-0123456789abcdef")
	f.Add("tskey-api-0123456789ab-0123456789abcdef")
	f.Add("tskey-client-0123456789ab-0123456789abcdef")
	f.Add("tskey-scim-0123456789ab-0123456789abcdef")
	f.Add("tskey-webhook-0123456789ab-0123456789abcdef")
	f.Add("tskey-auth-0123456789AB-0123456789ABCDEF")
	f.Add("tskey-auth-ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ-ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ")
	// The bytes standing just outside the three ranges a half is written in,
	// where a range test off by one shows itself.
	f.Add("tskey-auth-/0123456789ab-0123456789abcdef")
	f.Add("tskey-auth-0123456789ab:-0123456789abcdef")
	f.Add("tskey-auth-@0123456789ab-0123456789abcdef")
	f.Add("tskey-auth-0123456789ab[-0123456789abcdef")
	f.Add("tskey-auth-`0123456789ab-0123456789abcdef")
	f.Add("tskey-auth-0123456789ab{-0123456789abcdef")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef{")
	// The opening cut to its anchor and to one character in front of it, where
	// reading a candidate back would reach in front of the input.
	f.Add("key-auth-0123456789ab-0123456789abcdef")
	f.Add("skey-auth-0123456789ab-0123456789abcdef")
	f.Add("tskey-auth-0-1")     // one character in each half
	f.Add("tskey-auth-")        // the prefix alone
	f.Add("tskey-auth-0123")    // an identifier with no separator behind it
	f.Add("tskey-auth-0123-")   // a separator with no secret behind it
	f.Add("tskey-auth--0123")   // an identifier of no characters
	f.Add("tskey-auth-0123--4") // a secret of no characters
	f.Add("tskey-auth-0123456789_ab-0123456789abcdef")
	f.Add("tskey-auth-0123456789ab-0123456789_abcdef")
	f.Add("tskey-oauth-0123456789ab-0123456789abcdef") // a kind tailscale does not write
	f.Add("tskey-authx-0123456789ab-0123456789abcdef") // a kind with a character after it
	f.Add("tskey-AUTH-0123456789ab-0123456789abcdef")
	f.Add("TSKEY-auth-0123456789ab-0123456789abcdef")
	f.Add("tskey-0123456789ab-0123456789abcdef") // no kind at all
	f.Add("tskey_auth_0123456789ab_0123456789abcdef")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef-suffix")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef_suffix")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef tskey-api-0123456789AB-0123456789ABCDEF")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef\ntskey-api-0123456789AB-0123456789ABCDEF")
	// A key beginning inside the match before it, which a scan resuming past a
	// match steps over, and keys written into one another.
	f.Add("tskey-api-tskey-auth-0-1")
	// The tailnet-lock wrapping, whole and in every way it is not one.
	f.Add("tskey-auth-0123456789ab-0123456789abcdef--TL0123456789abcdef-0123456789abcdefghij")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef--TL0123456789ab+/ef-0123456789abcdefghij")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef--TL0123456789abcdef")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef--TL-0123456789abcdefghij")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef--TL0123456789abcdef- and prose")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef--Tl0123456789abcdef-0123456789abcdefghij")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef-TL0123456789abcdef-0123456789abcdefghij")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef--TL0123456789_abcdef-0123456789abcdefghij")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef--TL0123456789abcdef-0123456789_abcdefghij")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef--TL0123456789abcdef-0123456789abcdefghij==")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef--")
	f.Add("tskey-auth-0123456789ab-0123456789abcdef--T")
	// The suffix behind kinds Tailscale never wraps, and behind the one it does.
	f.Add("tskey-auth-a-b--TLxy-z")
	f.Add("tskey-api-a-b--TLxy-z")
	f.Add("tskey-client-a-b--TLxy-z")
	f.Add("tskey-scim-a-b--TLxy-z")
	f.Add("tskey-webhook-a-b--TLxy-z")
	// A wrapped key written into a path, which the private key's run walks
	// through because standard base64 admits the solidus.
	f.Add("tskey-auth-0123456789ab-0123456789abcdef--TL0123456789abcdef-0123456789abcdefghij/next/segment")
	f.Add(strings.Repeat("tskey-api-", 8) + "0-1")
	// Candidate positions crowded as close as a prefix allows, with no
	// identifier behind any of them.
	f.Add(strings.Repeat("tskey-auth-.", 8))
	f.Add(strings.Repeat("tskey-", 8))
	// The letters of the opening as ordinary text writes them.
	f.Add("https://login.tailscale.com/machine/register")
	f.Add("tailscale up --authkey tskey-auth-0123456789ab-0123456789abcdef")

	fuzzAgainstReference(f, TailscaleKey().Find, referenceTailscaleKeyFind)
}

// tailscaleKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func tailscaleKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line opens the prefix, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key. It carries the anchor once, in a word a line
	// about Tailscale is likely to hold.
	line := `time=2026-08-17T00:00:00Z level=info msg="auth key accepted" url=https://login.tailscale.com/machine/register `
	key := "tskey-auth-0123456789ab-0123456789abcdef"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every twelve characters with no identifier behind any
			// of them: each reaches the body of the loop and none becomes a
			// key. What it times is the walk over a run being started and
			// stopped, once per candidate and no more.
			name:  "candidates that are not values",
			src:   strings.Repeat("tskey-auth-.", 128),
			spans: 0,
		},
		{
			// Keys written into one another, each beginning ten characters into
			// the one in front of it. This is what the scan gets away with
			// keeping no cursor for: no run of the line is read as an
			// identifier twice, nor as a secret twice.
			name:  "keys written into one another",
			src:   strings.Repeat("tskey-api-", 128) + "0-1",
			spans: 128,
		},
		{
			name:  "one value",
			src:   line + "authkey=" + key,
			spans: 1,
		},
		{
			// The same value with the tailnet-lock wrapping behind it, which is
			// the branch that reads two runs of a second alphabet.
			name:  "one wrapped value",
			src:   line + "authkey=" + key + "--TL0123456789abcdef-0123456789abcdefghij",
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "authkey=" + key,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"authkey="+key+"\n", 32),
			spans: 32,
		},
	}
}
