package mask

import (
	"io"
	"slices"
	"strings"
	"testing"
)

// The Stripe publishable key pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The restricted, secret and organization keys are the other half of Stripe's
// format and have a file of their own. A case here carries one only where what
// is being stated is that this pattern leaves it alone, or where the two
// patterns are being held to a claim about each other.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. The run they are built from, 0123456789abcdef, is
// written out until the body is twenty-four characters, which is the shortest
// the scan reads — a floor, so a body shortened for readability would leave a
// case holding no key at all.

func Test_StripePublishableKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a live publishable key on its own",
			src:  "pk_live_0123456789abcdef01234567",
			want: []Span{{0, 32}},
		},
		{
			name: "a test publishable key",
			src:  "pk_test_0123456789abcdef01234567",
			want: []Span{{0, 32}},
		},
		{
			name: "a key in an environment assignment",
			src:  "STRIPE_PUBLISHABLE_KEY=pk_live_0123456789abcdef01234567",
			want: []Span{{23, 55}},
		},
		{
			// The count is read as a floor, so the ninety-nine characters
			// Stripe issues behind a prefix today are one key and not a key
			// with seventy-five characters left over.
			name: "the length Stripe issues today",
			src:  "pk_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
			want: []Span{{0, 107}},
		},
		{
			name: "a body written in capitals",
			src:  "pk_live_0123456789ABCDEF01234567",
			want: []Span{{0, 32}},
		},
		{
			// The span reaches the end of the run, so a run longer than the
			// floor is a key to the end of it rather than a key and a character
			// left over.
			name: "a run one character longer than the floor",
			src:  "pk_live_0123456789abcdef01234567z",
			want: []Span{{0, 33}},
		},
		{
			name: "a key after an underscore",
			src:  "STRIPE_KEY_pk_live_0123456789abcdef01234567",
			want: []Span{{11, 43}},
		},
		{
			name: "two keys separated by a space",
			src:  "pk_live_0123456789abcdef01234567 pk_test_0123456789abcdef01234567",
			want: []Span{{0, 32}, {33, 65}},
		},
		{
			// A publishable key written straight onto the end of a secret one.
			// The byte in front is a digit, and a whole body of them stands
			// behind it, which is a key and not a word. So this key is located
			// where one written against a word would not be, and a caller
			// running this pattern alone gets it — the secret key in front of
			// it being no business of this half.
			name: "a key written straight onto the end of a secret key",
			src:  "sk_live_0123456789abcdef01234567pk_test_0123456789abcdef01234567",
			want: []Span{{32, 64}},
		},
		{
			// The same two with an underscore between them, which is a byte a
			// key may be written after.
			name: "an underscore between a secret key and one of these",
			src:  "sk_live_0123456789abcdef01234567_pk_test_0123456789abcdef01234567",
			want: []Span{{33, 65}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := StripePublishableKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripePublishableKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "pk_live_",
		},
		{
			// Twenty-three characters where the pattern asks for twenty-four.
			// This is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which builtin_stripe_secret_key.go weighs for
			// both halves of the format.
			name: "a body one character too short",
			src:  "pk_live_0123456789abcdef0123456",
		},
		{
			// The key type with nothing between it and the body. The mode is
			// read as one of the names Stripe writes rather than as any word at
			// all, which is what keeps a two letter prefix from anchoring this.
			name: "a key type with no mode behind it",
			src:  "pk_0123456789abcdef01234567",
		},
		{
			// gitleaks reads prod beside live and test. Stripe documents no
			// such mode, so it is not read here.
			name: "a mode no Stripe page names",
			src:  "pk_prod_0123456789abcdef01234567",
		},
		{
			// The three key types that must not be exposed, which belong to the
			// pattern in builtin_stripe_secret_key.go. This pattern carries no
			// name for them, which is what the boundary between the two is.
			name: "a secret key",
			src:  "sk_live_0123456789abcdef01234567",
		},
		{
			name: "a restricted key",
			src:  "rk_live_0123456789abcdef01234567",
		},
		{
			name: "an organization key",
			src:  "sk_org_0123456789abcdef01234567",
		},
		{
			name: "an uppercase prefix",
			src:  "PK_LIVE_0123456789abcdef01234567",
		},
		{
			// The prefix is written with underscores, which is what tells this
			// format apart from the Anthropic and OpenAI keys written with
			// hyphens.
			name: "hyphens where the prefix carries underscores",
			src:  "pk-live-0123456789abcdef01234567",
		},
		{
			// The underscore is not in the alphabet a body is written in, so
			// the body here is the sixteen characters in front of it.
			name: "an underscore in the body",
			src:  "pk_live_0123456789abcdef_01234567",
		},
		{
			name: "a hyphen in the body",
			src:  "pk_live_0123456789abcdef-01234567",
		},
		{
			name: "a dot in the body",
			src:  "pk_live_0123456789abcdef.01234567",
		},
		{
			name: "a space in the body",
			src:  "pk_live_0123456789abcdef 01234567",
		},
		{
			name: "a body broken by a line break",
			src:  "pk_live_0123456789abcdef\n01234567",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// the whole of the anchor, so a run long enough is not a key
			// without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdef01234567",
		},
		{
			// The byte in front, which buys less here than it does for the
			// secret keys because fewer words close on this key type. It is
			// kept because the two halves of one format may not disagree about
			// where a key may begin.
			name: "a letter in front of the prefix",
			src:  "xpk_live_0123456789abcdef01234567",
		},
		{
			// What does close on this key type: topk_ is how the top-k
			// operation is spelled in a name, so topk_live_ carries a whole
			// prefix and a fixture name goes on in exactly the shape a key
			// does. The letter in front is what turns it away, which is what
			// task_test_ is to the secret keys.
			name: "a snake_case name whose segment closes the publishable key type",
			src:  "topk_live_0123456789abcdef01234567",
		},
		{
			name: "a digit in front of the prefix",
			src:  "1pk_live_0123456789abcdef01234567",
		},
		{
			name: "plain prose",
			src:  "there is no credential in this sentence",
		},
		{
			// Forty hexadecimal characters. A digest carries no underscore, so
			// it holds no prefix to be found at however long it runs.
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := StripePublishableKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_StripePublishableKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "STRIPE_PUBLISHABLE_KEY=pk_live_0123456789abcdef01234567",
			want: "STRIPE_PUBLISHABLE_KEY=********************************",
		},
		{
			name: "quoted",
			src:  `"pk_live_0123456789abcdef01234567"`,
			want: `"********************************"`,
		},
		{
			name: "json",
			src:  `{"publishableKey":"pk_live_0123456789abcdef01234567"}`,
			want: `{"publishableKey":"********************************"}`,
		},
		{
			// How a publishable key actually reaches text a caller masks: the
			// script that initializes a page with it.
			name: "a stripe.js initialization",
			src:  "const stripe = Stripe('pk_live_0123456789abcdef01234567');",
			want: "const stripe = Stripe('********************************');",
		},
		{
			name: "twice",
			src:  "pk_live_0123456789abcdef01234567 pk_test_0123456789abcdef01234567",
			want: "******************************** ********************************",
		},
	}

	m := New(WithPatterns(StripePublishableKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripePublishableKey_afterAWordCharacter(t *testing.T) {
	// The demand this pattern shares with the secret keys and with Slack: the
	// byte in front of a prefix may be no letter and no digit.
	//
	// It is not the word boundary a regular expression writes, and the
	// difference is the underscore: a key reaching a log line from a shell
	// stands against one, and a \b there would drop the key rather than trim
	// it. The three cases below are the two sides of that and what it costs.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "an underscore in front, which a key is written after",
			src:  "STRIPE_PUBLISHABLE_KEY_pk_live_0123456789abcdef01234567",
			want: "STRIPE_PUBLISHABLE_KEY_********************************",
		},
		{
			name: "a letter in front",
			src:  "xpk_live_0123456789abcdef01234567",
			want: "xpk_live_0123456789abcdef01234567",
		},
		{
			name: "a digit in front",
			src:  "1pk_live_0123456789abcdef01234567",
			want: "1pk_live_0123456789abcdef01234567",
		},
	}

	m := New(WithPatterns(StripePublishableKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripePublishableKey_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a key ends is
	// where its alphabet stops, so ordinary punctuation ends one and nothing
	// written after it joins it — but a letter or a digit written straight
	// against a key is redacted with the key, which is what buys a key of a
	// length nobody has published being located whole.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is pk_live_0123456789abcdef01234567.",
			want: "the key is ********************************.",
		},
		{
			name: "a word against the key",
			src:  "pk_live_0123456789abcdef01234567suffix",
			want: "**************************************",
		},
		{
			name: "an underscore against the key, which ends the run",
			src:  "pk_live_0123456789abcdef01234567_suffix",
			want: "********************************_suffix",
		},
		{
			name: "a hyphenated word against the key, which ends the run",
			src:  "pk_live_0123456789abcdef01234567-suffix",
			want: "********************************-suffix",
		},
	}

	m := New(WithPatterns(StripePublishableKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripePublishableKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted, and what it buys: the placeholder a template carries where a
	// publishable key goes is the shape a lower floor would draw in, and it is
	// written into documentation far more often than a key is.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key one character short of the floor",
			src:  "STRIPE_PUBLISHABLE_KEY=pk_live_0123456789abcdef0123456",
		},
		{
			name: "a key cut off at its prefix",
			src:  "STRIPE_PUBLISHABLE_KEY=pk_live_",
		},
		{
			name: "a placeholder where a key goes",
			src:  "STRIPE_PUBLISHABLE_KEY=pk_test_yourkeyhere",
		},
	}

	m := New(WithPatterns(StripePublishableKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_StripePublishableKey_insideASnakeCaseName(t *testing.T) {
	// What this pattern redacts that nobody issued. A prefix carries two
	// underscores, so no base64 payload holds one and no digest does; what is
	// left is text somebody wrote — a name whose first segment ends in pk,
	// whose second is a mode, and whose third is twenty-four unbroken letters
	// and digits.
	//
	// The cases are held to being redacted rather than to being spared, for the
	// reason the secret keys' file gives: such a name is a key's format exactly,
	// so nothing is left in the text to read the two apart by. What the cases
	// are for is that they move with the scan.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a name whose segments spell a prefix, with a digest behind it",
			src:  "pk_live_0123456789abcdef0123456789abcdef",
			want: "****************************************",
		},
		{
			name: "the same name at the start of a shell word",
			src:  "cat pk_test_0123456789abcdef01234567.json",
			want: "cat ********************************.json",
		},
	}

	m := New(WithPatterns(StripePublishableKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripePublishableKey_locatesEveryKeyOfARun(t *testing.T) {
	// The claim builtin_stripe_publishable_key.go makes: a key written against
	// a key is a key. The byte in front turns away a candidate written inside a
	// word, and a body is written in the characters a word is made of, so
	// without the exemption for a candidate opening in front of what the scan
	// has already reached, every key after the first of a run would be turned
	// away by the body in front of it and left in the text whole.
	//
	// What is asked below is therefore coverage and not separation: the spans
	// of such a run overlap by the two characters a run reaches into the prefix
	// behind it, and what may not happen is a key left out of them.
	body := "0123456789abcdef01234567"
	p := StripePublishableKey()

	for _, outer := range stripePublishableKeyPrefixes {
		for _, inner := range stripePublishableKeyPrefixes {
			for _, src := range []string{
				outer + body + inner + body,
				outer + inner + body,
				outer + body[:len(body)-1] + inner + body,
				outer + body + "_" + inner + body,
			} {
				tail := len(src) - (len(inner) + len(body))
				spans, _ := p.Find(src)
				if !coversFrom(src, spans, tail) {
					t.Errorf("Find(%q) = %v, which leaves the key at %d in the text", src, spans, tail)
				}
			}
		}
	}
}

func Test_stripeKeys_locateEveryKeyOfAMixedRun(t *testing.T) {
	// The claim both halves of Stripe's format make about each other: a key of
	// either kind written against a key of either kind is a key. The two read
	// one body between them through isStripeKeyBodyRunBefore, so the exemption
	// each of them carries has to hold across the pair as well — and what the
	// two report together overlaps, by the two characters a run reaches into
	// the prefix behind it, which a Masker merges.
	//
	// It cannot be stated from either file alone and is not a claim one input
	// can carry, so every prefix of each kind is written into every prefix of
	// the other, in both directions and in the four positions the per-pattern
	// tests use.
	body := "0123456789abcdef01234567"
	publishable := StripePublishableKey()
	secret := StripeSecretKey()

	kinds := [][]string{stripePublishableKeyPrefixes[:], stripeSecretKeyPrefixes[:]}
	for _, outers := range kinds {
		for _, inners := range kinds {
			for _, outer := range outers {
				for _, inner := range inners {
					for _, src := range []string{
						outer + body + inner + body,
						outer + inner + body,
						outer + body[:len(body)-1] + inner + body,
						outer + body + "_" + inner + body,
					} {
						tail := len(src) - (len(inner) + len(body))
						pub, _ := publishable.Find(src)
						sec, _ := secret.Find(src)
						spans := append(pub, sec...)
						if !coversFrom(src, spans, tail) {
							t.Errorf("the two patterns report %v on %q, which leaves the key at %d in the text", spans, src, tail)
						}
					}
				}
			}
		}
	}
}

func Test_stripeKeys_locateAMixedRunThroughAWindow(t *testing.T) {
	// The same run, read the way a stream reads it. Test_stripeKeys_locateEveryKeyOfAMixedRun
	// hands the whole text to Find at once, where a Writer hands it a window:
	// LookBehind bytes in front of what it has still to write out, and no more.
	//
	// A rule reading further back than that is a rule a window cannot
	// reproduce. It would locate the key when handed the text entire and leave
	// it when handed the window, so Mask would redact what a Writer released —
	// and the keys Stripe issues today are ninety-nine characters behind the
	// prefix, which is further back than LookBehind reaches. The bodies here
	// are that length for that reason: at the shortest they fit inside the
	// window and the difference cannot show.
	long := strings.Repeat("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 2)[:99]
	for _, tt := range []struct{ name, src string }{
		{"a secret key against a publishable one", "log: pk_live_" + long + "sk_live_" + long + " end\n"},
		{"a publishable key against a secret one", "log: sk_live_" + long + "pk_live_" + long + " end\n"},
		{"a run of secret keys", "log: sk_live_" + long + "sk_live_" + long + "sk_live_" + long + " end\n"},
	} {
		for _, set := range []struct {
			name     string
			patterns []Pattern
		}{
			{"secret alone", []Pattern{StripeSecretKey()}},
			{"publishable alone", []Pattern{StripePublishableKey()}},
			{"both", StripePatterns()},
		} {
			t.Run(tt.name+"/"+set.name, func(t *testing.T) {
				m := New(WithPatterns(set.patterns...))
				want := m.Mask(tt.src)
				for _, piece := range []int{1, 8, 64, 200} {
					var out strings.Builder
					w := NewWriter(&out, m)
					for i := 0; i < len(tt.src); i += piece {
						if _, err := io.WriteString(w, tt.src[i:min(i+piece, len(tt.src))]); err != nil {
							t.Fatalf("Write: %v", err)
						}
					}
					if err := w.Close(); err != nil {
						t.Fatalf("Close: %v", err)
					}
					if out.String() != want {
						t.Errorf("written %d byte(s) at a time gave %q, Mask gives %q", piece, out.String(), want)
					}
				}
			})
		}
	}
}

func Test_stripePublishableKeyPrefixes(t *testing.T) {
	// Four things hold the table together, and none of them shows anywhere
	// else.
	//
	// The anchor is what a candidate is read back to, and it stands at the
	// start of a candidate: an entry not opening with it is an entry the scan
	// never reaches. The character an entry closes with may not be one a body is
	// written in, which is what makes every body begin where a run begins — the
	// whole of why this scan needs no run cursor. The characters of the key type
	// an entry opens with — the anchor up to but not including the underscore
	// closing it — must all be ones a word is made of, which is what lets a name
	// close on the key type and so what the byte in front of a prefix is read
	// for. And no entry opens with another, so the first that matches is the
	// only one that could and the order they are tried in decides nothing.
	//
	// That last is where this table parts company with stripeSecretKeyPrefixes,
	// whose order is load-bearing because sk_org_ matches wherever sk_org_live_
	// does.
	if len(stripePublishableKeyPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}

	for i, prefix := range stripePublishableKeyPrefixes {
		t.Run(prefix, func(t *testing.T) {
			if len(prefix) <= len(stripePublishableKeyAnchor) {
				t.Fatalf("the prefix is too short to carry the anchor %q and a mode behind it", stripePublishableKeyAnchor)
			}
			if !strings.HasPrefix(prefix, stripePublishableKeyAnchor) {
				t.Errorf("the prefix does not open with %q, which the scan searches for, so no candidate is ever found at it", stripePublishableKeyAnchor)
			}
			if c := prefix[len(prefix)-1]; isBase62Byte(c) {
				t.Errorf("the prefix closes with %q, which a body may be written with, so a body need not begin where a run does", c)
			}
			for j := range len(stripePublishableKeyAnchor) - 1 {
				if c := prefix[j]; !isStripeKeyWordByte(c) {
					t.Errorf("the prefix holds %q at %d, which no word is written with, so nothing can close on the key type", c, j)
				}
			}
			for j := range i {
				if strings.HasPrefix(prefix, stripePublishableKeyPrefixes[j]) {
					t.Errorf("this prefix opens with %q in front of it, so the order of the table decides which is read", stripePublishableKeyPrefixes[j])
				}
			}
		})
	}
}

func Test_stripePublishableKeyAnchor(t *testing.T) {
	// Two things the scan rests on, and neither shows anywhere else.
	//
	// The anchor stands at the start of a candidate rather than inside one, so
	// a key begins where the anchor does and the arithmetic reading a candidate
	// back from the byte the search stops at is counted from the anchor's own
	// start — where the secret key scan counts from a byte standing inside the
	// key type.
	//
	// And it closes with a character no body is written with, which is what
	// keeps a run from holding two candidates and so what holds the scan
	// linear without a cursor.
	if !strings.HasPrefix(stripePublishableKeyPrefixes[0], stripePublishableKeyAnchor) {
		t.Fatalf("the anchor %q does not open a prefix, so the position a search reports is not where a key begins", stripePublishableKeyAnchor)
	}
	if len(stripePublishableKeyAnchor) < 2 {
		t.Error("the anchor is a single byte, which is the search this pattern is meant to be more selective than")
	}
	if c := stripePublishableKeyAnchor[len(stripePublishableKeyAnchor)-1]; isBase62Byte(c) {
		t.Errorf("the anchor closes with %q, which a body may be written with, so a run could hold two candidates", c)
	}

	// And the byte the search stops at stands at the index a candidate is read
	// back from. builtin_scan.go says why that is held here rather than left to
	// the targets.
	if stripePublishableKeyAnchorIndex >= len(stripePublishableKeyAnchor) {
		t.Fatalf("the search stops at %d, the anchor is %d characters", stripePublishableKeyAnchorIndex, len(stripePublishableKeyAnchor))
	}
	if c := stripePublishableKeyAnchor[stripePublishableKeyAnchorIndex]; c != stripePublishableKeyAnchorByte {
		t.Errorf("the anchor carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(stripePublishableKeyAnchorByte))
	}
}

func Test_stripePublishableKeyPrefixAt(t *testing.T) {
	// Which prefix is read at a position, and how much of it. What the length
	// then buys is where the body begins.
	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "a live key",
			src:  "pk_live_0123456789abcdef01234567",
			want: 8,
		},
		{
			name: "a test key",
			src:  "pk_test_0123456789abcdef01234567",
			want: 8,
		},
		{
			name: "a secret key, which belongs to the other pattern",
			src:  "sk_live_0123456789abcdef01234567",
			want: 0,
		},
		{
			name: "a mode no Stripe page names",
			src:  "pk_prod_0123456789abcdef01234567",
			want: 0,
		},
		{
			name: "a key type with no mode behind it",
			src:  "pk_0123456789abcdef01234567",
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripePublishableKeyPrefixAt(tt.src, 0); got != tt.want {
				t.Errorf("stripePublishableKeyPrefixAt(%q, 0) = %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripePublishableKey_scanIsLinear(t *testing.T) {
	// This scan reads a run to its end and keeps no cursor, so what holds it
	// linear is a property of the format rather than state: every prefix closes
	// with an underscore, no body is written with one, and so no two candidates
	// can read the same run.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole body apiece and so hold a candidate every thirty-two bytes at their
	// densest. The crowding a line can actually carry, a candidate every eight,
	// stays here.
	sources := map[string]string{
		// A candidate every eight characters, each with a run of two behind it,
		// so every one of them is rejected on the floor.
		"a candidate every eight characters": strings.Repeat("pk_live_", 250000),
		// The same crowding with a whole key at each candidate, so every one of
		// them reads its own run to the end and reports a span.
		"a key every thirty-two characters": strings.Repeat("pk_live_0123456789abcdef01234567", 60000),
		// Nothing but the three bytes a candidate is read back to, so every
		// position reaches the prefix table and none goes further.
		"an anchor every three characters": strings.Repeat("pk_", 700000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the line and finding a key.
		"a body that runs the length of the line": "pk_live_" + strings.Repeat("a", 2000000),
		// One candidate with no prefix, whose run is the whole line and is
		// never walked at all.
		"a run that runs the length of the line": "pk_" + strings.Repeat("a", 2000000),
	}

	checkScanIsLinear(t, StripePublishableKey(), sources)
}

// referenceStripePublishableKeyFind locates keys the plain way: every position
// in turn, the byte in front of it read, each prefix tried at it and the body
// behind that walked to the end of its run, with nothing remembered between
// candidates. The prefixes, the floor and the two character classes are spelled
// again here rather than shared with the scan. A reference reading those
// declarations could not disagree with it about them, and it is exactly that
// disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
//
// Every position is a starting point in its own right, a match included. No key
// can begin inside the span of another here, which
// builtin_stripe_publishable_key.go sets out, so nothing turns on asking at a
// position a match already covers — but the reference is written to know
// nothing the scan claims, and where the scan resumes is one of the things the
// target below is for.
//
// It is written out rather than built on a regular expression, for the reason
// the secret keys' reference gives: the byte this pattern reads in front of a
// prefix is not the word boundary an expression writes, \b counts the
// underscore as a word character, and there is no lookbehind to write the
// demand with instead.
func referenceStripePublishableKeyFind(src string) []Span {
	const bodyChars = 24
	prefixes := []string{"pk_live_", "pk_test_"}

	word := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
	}
	body := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
	}

	// A body written against a candidate is no word, which is what lets a key
	// written against a key be a key. It reads back exactly the shortest body
	// and no further, so the answer at a position rests on nothing a window
	// could not be handed.
	runBefore := bodyChars - 2 // every prefix opens with two characters and an underscore
	bodyRunBefore := func(i int) bool {
		if i < runBefore {
			return false
		}
		for j := i - runBefore; j < i; j++ {
			if !body(src[j]) {
				return false
			}
		}
		return true
	}

	var spans []Span
	for start := range len(src) {
		if start > 0 && word(src[start-1]) && !bodyRunBefore(start) {
			continue
		}
		from := -1
		for _, prefix := range prefixes {
			if strings.HasPrefix(src[start:], prefix) {
				from = start + len(prefix)
				break
			}
		}
		if from < 0 {
			continue
		}

		end := from
		for end < len(src) && body(src[end]) {
			end++
		}
		if end-from < bodyChars {
			continue
		}
		spans = append(spans, Span{Start: start, End: end})
	}
	return spans
}

// FuzzStripePublishableKey_matchesReference guards the hand-written scan: the
// three bytes it searches for, the byte it reads in front of a prefix, the
// floor it holds a body to, the alphabet it reads that body in and the byte it
// resumes at may none of them change which keys are located.
//
// The seeds spell each prefix once and then the edges the anchor, the floor and
// the byte in front live on — a body one character short, a mode nobody names,
// a key closing a word, a key written inside another, the three key types this
// pattern declines, and a line that is nothing but anchors. There is no
// checked-in corpus for this target, so what the seeds reach is all a cold run
// starts from.
func FuzzStripePublishableKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("STRIPE_PUBLISHABLE_KEY=pk_live_0123456789abcdef01234567")
	f.Add("pk_test_0123456789abcdef01234567")
	f.Add("sk_live_0123456789abcdef01234567") // the other half of the format
	f.Add("rk_live_0123456789abcdef01234567")
	f.Add("sk_org_0123456789abcdef01234567")
	f.Add("pk_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012") // the length Stripe issues today
	f.Add("pk_live_0123456789abcdef0123456")                                                                             // one short of a body
	f.Add("pk_live_0123456789abcdef01234567z")                                                                           // and a run longer than one
	f.Add("pk_live_")                                                                                                    // a prefix with no body at all
	f.Add("pk_0123456789abcdef01234567")                                                                                 // a key type with no mode behind it
	f.Add("pk_prod_0123456789abcdef01234567")                                                                            // a mode no Stripe page names
	f.Add("PK_LIVE_0123456789abcdef01234567")                                                                            // an uppercase prefix
	f.Add("pk-live-0123456789abcdef01234567")                                                                            // hyphens where the prefix carries underscores
	f.Add("pk_live_0123456789abcdef_01234567")                                                                           // an underscore ends the body
	f.Add("pk_live_0123456789abcdef-01234567")                                                                           // and so does a hyphen
	f.Add("STRIPE_PUBLISHABLE_KEY_pk_live_0123456789abcdef01234567")                                                     // an underscore in front, which a key is written after
	f.Add("xpk_live_0123456789abcdef01234567")                                                                           // a letter in front of the prefix
	f.Add("pk_live_0123456789abcdef01234567 pk_test_0123456789abcdef01234567")
	f.Add("pk_live_0123456789abcdef01234567\npk_test_0123456789abcdef01234567")
	// A key beginning inside the span of the one before it, which a scan
	// resuming past a match steps over, and one written after a secret key.
	f.Add("pk_live_0123456789abcdef01234567pk_test_0123456789abcdef01234567")
	f.Add("sk_live_0123456789abcdef01234567pk_test_0123456789abcdef01234567")
	f.Add("sk_live_0123456789abcdef01234567_pk_test_0123456789abcdef01234567")
	// Candidate positions crowded as close as they can be, with a body behind
	// none of them, and the bytes a candidate is read back to on their own.
	f.Add(strings.Repeat("pk_live_", 8))
	f.Add(strings.Repeat("pk_", 24))
	// The prefix written inside a run of the alphabet, which the byte in front
	// of it turns away, and written after one that ends.
	f.Add("payload=zzzzpk_live_0123456789abcdef01234567zzzz")
	f.Add("payload=zzzz_pk_live_0123456789abcdef01234567zzzz")

	fuzzAgainstReference(f, StripePublishableKey().Find, referenceStripePublishableKeyFind)
}

// stripePublishableKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func stripePublishableKeyFindBenchmarks() []benchmarkCase {
	// An ordinary line carries the byte the scan searches for about once, so
	// what the line times is that search and the one position it stops at —
	// which is most of what this pattern costs a caller whose text holds no
	// key.
	line := `time=2026-08-17T00:00:00Z level=info msg="rendering the checkout" url=https://api.stripe.com/v1/charges `
	key := "pk_live_0123456789abcdef01234567"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate every eight characters with a run of two behind each,
			// so every one of them reaches the prefix table and none becomes a
			// key. What it times is the anchor being found and the floor
			// turning a candidate away.
			name:  "candidates that are not values",
			src:   strings.Repeat("pk_live_", 128),
			spans: 0,
		},
		{
			// A name closing on the key type at every candidate, which is the
			// one byte in front turning each of them away before the prefix
			// table is reached at all. topk_ is what the rationale in
			// builtin_stripe_publishable_key.go names as the shape that
			// carries a whole prefix, and it is what this guard is kept for.
			name:  "a name closing on the key type",
			src:   strings.Repeat("topk_live_0123456789abcdef01234567 ", 128),
			spans: 0,
		},
		{
			// Keys crowded as close as a separator lets them be, which is the
			// densest a run of them can be located. What it times is the walk
			// over a body, once per key and no more.
			name:  "keys crowded on one line",
			src:   strings.Repeat(key+" ", 128),
			spans: 128,
		},
		{
			// One key whose body is far longer than any Stripe issues, which is
			// the walk over a run reading to the end of a line and finding a
			// key there.
			name:  "one long body",
			src:   "pk_live_" + strings.Repeat("0123456789abcdef", 256),
			spans: 1,
		},
		{
			name:  "one value",
			src:   line + "key=" + key,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "key=" + key,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"key="+key+"\n", 32),
			spans: 32,
		},
	}
}
