package mask

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// The Stripe secret key pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a
// set of tests apiece.
//
// The publishable key is the other half of Stripe's format and has a file of
// its own. A case here carries one only where what is being stated is that this
// pattern leaves it alone.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. The run they are built from, 0123456789abcdef, is
// written out until the body is twenty-four characters, which is the shortest
// the scan reads — a floor, so a body shortened for readability would leave a
// case holding no key at all. One case carries the ninety-nine characters
// Stripe issues today, to say that the floor is not a count.

func Test_StripeSecretKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a live secret key on its own",
			src:  "sk_live_0123456789abcdef01234567",
			want: []Span{{0, 32}},
		},
		{
			name: "a secret key in an environment assignment",
			src:  "STRIPE_SECRET_KEY=sk_live_0123456789abcdef01234567",
			want: []Span{{18, 50}},
		},
		{
			name: "a test secret key",
			src:  "sk_test_0123456789abcdef01234567",
			want: []Span{{0, 32}},
		},
		{
			name: "a live restricted key",
			src:  "rk_live_0123456789abcdef01234567",
			want: []Span{{0, 32}},
		},
		{
			name: "a test restricted key",
			src:  "rk_test_0123456789abcdef01234567",
			want: []Span{{0, 32}},
		},
		{
			// Stripe states the prefix sk_org and does not state where the mode
			// of an organization key is written. Both readings are in the
			// table, so a key carrying no mode segment is located here and a
			// key carrying one is located in the case below.
			name: "an organization key with no mode segment",
			src:  "sk_org_0123456789abcdef01234567",
			want: []Span{{0, 31}},
		},
		{
			name: "an organization key with a mode segment of its own",
			src:  "sk_org_live_0123456789abcdef01234567",
			want: []Span{{0, 36}},
		},
		{
			name: "an organization key in a sandbox",
			src:  "sk_org_test_0123456789abcdef01234567",
			want: []Span{{0, 36}},
		},
		{
			// The ninety-nine characters Stripe issues behind a prefix today.
			// The count is read as a floor, so this is one key and not a key
			// with seventy-five characters left over.
			name: "the length Stripe issues today",
			src:  "sk_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012",
			want: []Span{{0, 107}},
		},
		{
			name: "a body written in capitals",
			src:  "sk_live_0123456789ABCDEF01234567",
			want: []Span{{0, 32}},
		},
		{
			// The span reaches the end of the run, so a run longer than the
			// floor is a key to the end of it rather than a key and a character
			// left over.
			name: "a run one character longer than the floor",
			src:  "sk_live_0123456789abcdef01234567z",
			want: []Span{{0, 33}},
		},
		{
			// A publishable key written straight onto the end of a secret one.
			// The second begins against a digit, so it opens nothing for either
			// pattern, and the first is redacted to the end of its run — which
			// reaches the two characters of the publishable key type and stops
			// at the underscore behind them. That is what the byte in front
			// costs, and it is the shape nobody writes: a list of keys carries
			// a separator.
			name: "a publishable key written straight onto the end of one of these",
			src:  "sk_live_0123456789abcdef01234567pk_test_0123456789abcdef01234567",
			want: []Span{{0, 34}},
		},
		{
			// The same two keys with an underscore between them, which is a
			// byte a key may be written after. This pattern takes the first;
			// the publishable one takes the second.
			name: "an underscore between one of these and a publishable key",
			src:  "sk_live_0123456789abcdef01234567_pk_test_0123456789abcdef01234567",
			want: []Span{{0, 32}},
		},
		{
			name: "a key after an underscore",
			src:  "STRIPE_KEY_sk_live_0123456789abcdef01234567",
			want: []Span{{11, 43}},
		},
		{
			name: "two keys separated by a space",
			src:  "sk_live_0123456789abcdef01234567 rk_live_0123456789abcdef01234567",
			want: []Span{{0, 32}, {33, 65}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripeSecretKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripeSecretKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "sk_live_",
		},
		{
			// Twenty-three characters where the pattern asks for twenty-four.
			// This is the shape a line cut to a column limit leaves, and the
			// characters in front of the cut stay in the text: the far side of
			// reading a floor, which builtin_stripe_secret_key.go weighs.
			name: "a body one character too short",
			src:  "sk_live_0123456789abcdef0123456",
		},
		{
			// The key type with nothing between it and the body. The mode is
			// read as one of the names Stripe writes rather than as any word at
			// all, which is what keeps a two letter prefix from anchoring this.
			name: "a key type with no mode behind it",
			src:  "sk_0123456789abcdef01234567",
		},
		{
			// gitleaks reads prod beside live and test. Stripe documents no
			// such mode, so it is not read here.
			name: "a mode no Stripe page names",
			src:  "sk_prod_0123456789abcdef01234567",
		},
		{
			// sk_org_ matches, the body behind it is the four characters of
			// prod, and four is short of the floor. An organization key in a
			// mode Stripe has not written is located nowhere, which is the same
			// wager the case above states.
			name: "an organization key in a mode no Stripe page names",
			src:  "sk_org_prod_0123456789abcdef01234567",
		},
		{
			// The publishable key type, which is the other half of Stripe's
			// format and belongs to the pattern in
			// builtin_stripe_publishable_key.go. This pattern carries no name
			// for it, which is what the boundary between the two is.
			name: "a publishable key",
			src:  "pk_live_0123456789abcdef01234567",
		},
		{
			name: "a key type this pattern carries no name for",
			src:  "xk_live_0123456789abcdef01234567",
		},
		{
			name: "an uppercase prefix",
			src:  "SK_LIVE_0123456789abcdef01234567",
		},
		{
			// The prefix is written with underscores, which is what tells this
			// format apart from the Anthropic and OpenAI keys written with
			// hyphens.
			name: "hyphens where the prefix carries underscores",
			src:  "sk-live-0123456789abcdef01234567",
		},
		{
			// The underscore is not in the alphabet a body is written in, so
			// the body here is the sixteen characters in front of it.
			name: "an underscore in the body",
			src:  "sk_live_0123456789abcdef_01234567",
		},
		{
			name: "a hyphen in the body",
			src:  "sk_live_0123456789abcdef-01234567",
		},
		{
			name: "a dot in the body",
			src:  "sk_live_0123456789abcdef.01234567",
		},
		{
			name: "a space in the body",
			src:  "sk_live_0123456789abcdef 01234567",
		},
		{
			name: "a body broken by a line break",
			src:  "sk_live_0123456789abcdef\n01234567",
		},
		{
			// A body of the right length opening with no prefix. The prefix is
			// the whole of the anchor, so a run long enough is not a key
			// without it.
			name: "a run of the right length opening with no prefix",
			src:  "0123456789abcdef01234567",
		},
		{
			// task_ closes with the whole of a secret key's key type, so a
			// fixture name goes on in exactly the shape a key does. The letter
			// in front of the prefix is what turns it away, and gitleaks holds
			// its own Stripe rule to this very input.
			name: "a snake_case name whose segment closes the secret key type",
			src:  "task_test_0123456789abcdef01234567",
		},
		{
			name: "a snake_case name whose segment closes the restricted key type",
			src:  "network_live_0123456789abcdef01234567",
		},
		{
			name: "a digit in front of the prefix",
			src:  "1sk_live_0123456789abcdef01234567",
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
			if got := StripeSecretKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_StripeSecretKey_inContext(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "assignment",
			src:  "STRIPE_SECRET_KEY=sk_live_0123456789abcdef01234567",
			want: "STRIPE_SECRET_KEY=********************************",
		},
		{
			name: "quoted",
			src:  `"sk_live_0123456789abcdef01234567"`,
			want: `"********************************"`,
		},
		{
			name: "json",
			src:  `{"restrictedKey":"rk_live_0123456789abcdef01234567"}`,
			want: `{"restrictedKey":"********************************"}`,
		},
		{
			// The way Stripe's own documentation writes a request: the key as
			// the basic auth username, closed by the colon that keeps curl from
			// asking for a password.
			name: "a curl command",
			src:  "curl https://api.stripe.com/v1/charges -u sk_live_0123456789abcdef01234567:",
			want: "curl https://api.stripe.com/v1/charges -u ********************************:",
		},
		{
			name: "a bearer token header",
			src:  "Authorization: Bearer rk_live_0123456789abcdef01234567",
			want: "Authorization: Bearer ********************************",
		},
		{
			name: "twice",
			src:  "sk_live_0123456789abcdef01234567 rk_live_0123456789abcdef01234567",
			want: "******************************** ********************************",
		},
		{
			// Two keys with an underscore between them, which is a byte a key
			// may be written after. Both go, and the underscore stays.
			name: "two keys with an underscore between them",
			src:  "sk_live_0123456789abcdef01234567_rk_test_0123456789abcdef01234567",
			want: "********************************_********************************",
		},
	}

	m := New(WithPatterns(StripeSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripeSecretKey_afterAWordCharacter(t *testing.T) {
	// The demand the Slack scan makes too: the byte in front of a prefix may
	// be no letter and no digit. Both key types here can close a word, so
	// without it a snake_case name is read as a key.
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
			src:  "STRIPE_SECRET_KEY_sk_live_0123456789abcdef01234567",
			want: "STRIPE_SECRET_KEY_********************************",
		},
		{
			name: "a letter in front, which is a word closing on the prefix",
			src:  "xsk_live_0123456789abcdef01234567",
			want: "xsk_live_0123456789abcdef01234567",
		},
		{
			name: "a digit in front",
			src:  "1sk_live_0123456789abcdef01234567",
			want: "1sk_live_0123456789abcdef01234567",
		},
	}

	m := New(WithPatterns(StripeSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripeSecretKey_reachesTheEndOfTheRun(t *testing.T) {
	// The far side of reading a floor rather than a count. Where a key ends is
	// where its alphabet stops, so ordinary punctuation ends one and nothing
	// written after it joins it — but a letter or a digit written straight
	// against a key is redacted with the key, which is what buys a key of a
	// length nobody has published being located whole.
	//
	// The alphabet is narrower than the Anthropic and OpenAI ones in the way
	// that matters most here: neither the underscore nor the hyphen is in it,
	// so the next segment of a snake_case name is left in the text rather than
	// swallowed.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a sentence",
			src:  "the key is sk_live_0123456789abcdef01234567.",
			want: "the key is ********************************.",
		},
		{
			name: "a shell assignment closed by a quote",
			src:  `export STRIPE_SECRET_KEY="sk_live_0123456789abcdef01234567"`,
			want: `export STRIPE_SECRET_KEY="********************************"`,
		},
		{
			name: "a word against the key",
			src:  "sk_live_0123456789abcdef01234567suffix",
			want: "**************************************",
		},
		{
			name: "an underscore against the key, which ends the run",
			src:  "sk_live_0123456789abcdef01234567_suffix",
			want: "********************************_suffix",
		},
		{
			name: "a hyphenated word against the key, which ends the run",
			src:  "sk_live_0123456789abcdef01234567-suffix",
			want: "********************************-suffix",
		},
	}

	m := New(WithPatterns(StripeSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripeSecretKey_cutShortOfTheFloor(t *testing.T) {
	// What the floor costs, held to being left in the text rather than
	// redacted. A line cut to a column limit partway through a key leaves a
	// prefix and a body too short to be one, and the random characters written
	// before the cut come through whole.
	//
	// It is the price of a grammar whose anchor is eight characters of prefix
	// and nothing else, and of a floor set where it turns the placeholder away.
	// The cases move with the scan: one of them starting to be located means
	// the floor moved, and that is a decision to be taken rather than noticed
	// afterwards.
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a key one character short of the floor",
			src:  "STRIPE_SECRET_KEY=sk_live_0123456789abcdef0123456",
		},
		{
			name: "a key cut off at its prefix",
			src:  "STRIPE_SECRET_KEY=sk_live_",
		},
		{
			// The other side of the same count: what a lower floor would draw
			// in is the placeholder a template carries where a key goes.
			name: "a placeholder where a key goes",
			src:  "STRIPE_SECRET_KEY=sk_test_yourkey",
		},
	}

	m := New(WithPatterns(StripeSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.src {
				t.Errorf("Mask(%q) = %q, want the text unchanged", tt.src, got)
			}
		})
	}
}

func Test_StripeSecretKey_insideASnakeCaseName(t *testing.T) {
	// What this pattern redacts that nobody issued. A prefix carries two
	// underscores, so no base64 payload holds one and no digest does; what is
	// left is text somebody wrote — a snake_case name whose first segment is a
	// key type, whose second is a mode, and whose third is twenty-four unbroken
	// letters and digits.
	//
	// The cases are held to being redacted rather than to being spared. Such a
	// name is a key's format exactly, so nothing is left in the text to read
	// the two apart by, and the only tightening on offer is the count;
	// builtin_stripe_secret_key.go sets out why this scan reads it as a floor.
	// What the cases are for is that they move with the scan: one of them
	// ceasing to be located means the grammar changed, and that is a decision
	// to be taken rather than noticed afterwards.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a name whose segments spell a prefix, with a digest behind it",
			src:  "rk_live_0123456789abcdef0123456789abcdef",
			want: "****************************************",
		},
		{
			name: "the same name at the start of a shell word",
			src:  "cat sk_test_0123456789abcdef01234567.json",
			want: "cat ********************************.json",
		},
	}

	m := New(WithPatterns(StripeSecretKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripeSecretKey_noKeyBeginsInsideAnother(t *testing.T) {
	// The claim builtin_stripe_secret_key.go makes: the spans of this pattern
	// never overlap one another, because a key begins
	// only where no letter and no digit stands in front of it and everything a
	// span covers is one or the other but for the underscores of the prefix —
	// none of which opens a prefix of its own.
	//
	// It is what the scan resuming past a match would rest on, were it to
	// resume there, and it is what the paragraph on the second of two keys
	// written together is about. Neither is a claim one input can state, so
	// every pair of prefixes is written into one another here: against the end
	// of a body, where a body begins, and one character short of a body so that
	// the outer candidate is rejected and the inner is all there is.
	body := "0123456789abcdef01234567"
	p := StripeSecretKey()

	for _, outer := range stripeSecretKeyPrefixes {
		for _, inner := range stripeSecretKeyPrefixes {
			for _, src := range []string{
				outer + body + inner + body,
				outer + inner + body,
				outer + body[:len(body)-1] + inner + body,
				outer + body + "_" + inner + body,
			} {
				spans := p.Find(src)
				for i, got := range spans {
					if i > 0 && got.Start < spans[i-1].End {
						t.Errorf("Find(%q) = %v, which holds two values overlapping", src, spans)
						break
					}
				}
			}
		}
	}
}

func Test_stripeSecretKeyPrefixes(t *testing.T) {
	// Four things hold the table together, and none of them shows anywhere else.
	//
	// The anchor is what the scan searches the input for, and a candidate opens
	// stripeSecretKeyAnchorIndex bytes in front of it: an entry not carrying it
	// there is an entry the scan never reaches. The character an entry closes
	// with may not be one a body is written in, which is what makes every body
	// begin where a run begins — the whole of why this scan needs no run cursor.
	// The characters an entry opens with, up to and including the first of the
	// anchor, must all be ones a word is made of: that is what lets a snake_case
	// name close on a key type, and so what the byte in front of a prefix is
	// read for at all. And the entries are ordered longest first, which here is
	// a rule and not the courtesy it is in the Slack and GitLab tables: sk_org_
	// matches wherever sk_org_live_ does, and the scan takes the first entry
	// that matches.
	if len(stripeSecretKeyPrefixes) == 0 {
		t.Fatal("the pattern carries no prefix, so it locates nothing")
	}

	for i, prefix := range stripeSecretKeyPrefixes {
		t.Run(prefix, func(t *testing.T) {
			if len(prefix) <= stripeSecretKeyAnchorIndex+len(stripeSecretKeyAnchor) {
				t.Fatalf("the prefix is too short to carry the anchor %q and a body behind it", stripeSecretKeyAnchor)
			}
			at := prefix[stripeSecretKeyAnchorIndex : stripeSecretKeyAnchorIndex+len(stripeSecretKeyAnchor)]
			if at != stripeSecretKeyAnchor {
				t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", at, stripeSecretKeyAnchor)
			}
			if c := prefix[len(prefix)-1]; isBase62Byte(c) {
				t.Errorf("the prefix closes with %q, which a body may be written with, so a body need not begin where a run does", c)
			}
			for j := range stripeSecretKeyAnchorIndex + 1 {
				if c := prefix[j]; !isStripeKeyWordByte(c) {
					t.Errorf("the prefix holds %q at %d, which no word is written with, so nothing can close on the key type", c, j)
				}
			}
			if i > 0 && len(prefix) > len(stripeSecretKeyPrefixes[i-1]) {
				t.Errorf("the prefix is longer than %q in front of it, so a longer prefix could be read as a shorter one and a body of the difference", stripeSecretKeyPrefixes[i-1])
			}
			for j := range i {
				if strings.HasPrefix(prefix, stripeSecretKeyPrefixes[j]) {
					t.Errorf("this prefix opens with %q in front of it, so it is never reached", stripeSecretKeyPrefixes[j])
				}
			}
		})
	}
}

func Test_stripeSecretKeyAnchor(t *testing.T) {
	// The scan resumes one byte past the anchor rather than one byte past the
	// start of the candidate, because resuming at the start would find the same
	// anchor again and never advance. That skips nothing only while two
	// candidates cannot begin one byte apart, and what settles it is that the
	// anchor cannot begin one byte into itself: a candidate at the next byte
	// would need the anchor's first character where this one carries its second.
	if len(stripeSecretKeyAnchor) < 2 {
		t.Fatal("the anchor is a single byte, so resuming past it is resuming past the candidate")
	}
	if stripeSecretKeyAnchor[0] == stripeSecretKeyAnchor[1] {
		t.Errorf("the anchor %q opens with the character behind it, so a candidate one byte along would be stepped over", stripeSecretKeyAnchor)
	}
}

func Test_isStripeKeyWordByte(t *testing.T) {
	// What may not stand in front of a Stripe prefix, stated over every byte
	// rather than by example. It holds the same characters as the base62
	// alphabet a body is written in and is asked separately, so that the day one
	// of them widens the other is not carried along with it.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z'
		if got := isStripeKeyWordByte(b); got != want {
			t.Errorf("isStripeKeyWordByte(%q) = %v, want %v", b, got, want)
		}
	}
}

func Test_stripeSecretKeyPrefixAt(t *testing.T) {
	// Which prefix is read at a position, and how much of it. What the length
	// then buys is where the body begins, so the organization cases are the
	// ones that matter: read as the shorter of the two, a key written with a
	// mode segment would be given a body of four characters.
	tests := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "a secret key",
			src:  "sk_live_0123456789abcdef01234567",
			want: 8,
		},
		{
			name: "a restricted key",
			src:  "rk_test_0123456789abcdef01234567",
			want: 8,
		},
		{
			name: "an organization key with no mode segment",
			src:  "sk_org_0123456789abcdef01234567",
			want: 7,
		},
		{
			name: "an organization key with a mode segment of its own",
			src:  "sk_org_live_0123456789abcdef01234567",
			want: 12,
		},
		{
			name: "a publishable key, which belongs to the other pattern",
			src:  "pk_live_0123456789abcdef01234567",
			want: 0,
		},
		{
			name: "a mode no Stripe page names",
			src:  "sk_prod_0123456789abcdef01234567",
			want: 0,
		},
		{
			name: "a key type with no mode behind it",
			src:  "sk_0123456789abcdef01234567",
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripeSecretKeyPrefixAt(tt.src, 0); got != tt.want {
				t.Errorf("stripeSecretKeyPrefixAt(%q, 0) = %d, want %d", tt.src, got, tt.want)
			}
		})
	}
}

func Test_StripeSecretKey_scanIsLinear(t *testing.T) {
	// This scan reads a run to its end and keeps no cursor, so what holds it
	// linear is a property of the format rather than state: every prefix
	// closes with an underscore, no body is written with one, and so no two
	// candidates can read the same run. A scan reaching linearity that way
	// drives inputs of its own for it rather than borrowing another's, since
	// what the argument rests on is this format's prefix and this format's
	// alphabet. These are the inputs that would find it wrong here — a line
	// that is nothing but candidates, a line that is nothing but anchors, and
	// a single run as long as the line.
	//
	// The generic guard in builtins_test.go repeats the samples, which carry a
	// whole body apiece and so hold a candidate every thirty-two bytes at their
	// densest. The crowding a line can actually carry, a candidate every eight,
	// stays here.
	sources := map[string]string{
		// A candidate every eight characters, each with a run of two behind it,
		// so every one of them is rejected on the floor.
		"a candidate every eight characters": strings.Repeat("sk_live_", 250000),
		// The same crowding with a whole key at each candidate, so every one of
		// them reads its own run to the end and reports a span.
		"a key every thirty-two characters": strings.Repeat("sk_live_0123456789abcdef01234567", 60000),
		// Nothing but the two bytes the scan searches for, so every position
		// reaches the test in front of the prefix table and none goes further.
		"an anchor every two characters": strings.Repeat("k_", 1000000),
		// A word closing on the key type at every candidate, which is the byte
		// in front turning each of them away.
		"a name closing on the key type at every candidate": strings.Repeat("task_test_", 200000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the line and finding a key.
		"a body that runs the length of the line": "sk_live_" + strings.Repeat("a", 2000000),
		// One candidate with no prefix, whose run is the whole line and is
		// never walked at all.
		"a run that runs the length of the line": "sk_" + strings.Repeat("a", 2000000),
	}

	m := New(WithPatterns(StripeSecretKey()))
	for name, src := range sources {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_ = m.Mask(src)
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("Mask() of %d bytes took %v", len(src), d)
			}
		})
	}
}

// referenceStripeSecretKeyFind locates keys the plain way: every position in
// turn, the byte in front of it read, each prefix tried at it and the body
// behind that walked to the end of its run, with nothing remembered between
// candidates. The prefixes, the floor and the two character classes are spelled
// again here rather than shared with the scan. A reference reading those
// declarations could not disagree with it about them, and it is exactly that
// disagreement the fuzz target below is for: the two have to be changed
// together or reported apart.
//
// Every position is a starting point in its own right, a match included. No key
// can begin inside the span of another here, which builtin_stripe_secret_key.go
// sets out, so nothing turns on asking at a position a match already covers —
// but the reference is written to know nothing the scan claims, and where the
// scan resumes is one of the things the target below is for.
//
// It is written out rather than built on a regular expression, for the reason
// the Slack reference gives: the byte this pattern reads in front of a prefix
// is not the word boundary an expression writes. \b in Go's syntax counts the
// underscore as a word character and would drop STRIPE_SECRET_KEY_sk_live_...
// entirely, and there is no lookbehind to write the demand with instead.
//
// Unlike the references beside it this one costs no more than the scan does.
// Walking the run at every position is what a cursor saves a scan from, and
// this scan keeps none: no two candidates can read the same run, so the walks
// here telescope exactly as the scan's do.
func referenceStripeSecretKeyFind(src string) []Span {
	const bodyChars = 24
	prefixes := []string{
		"sk_org_live_", "sk_org_test_",
		"sk_live_", "sk_test_",
		"rk_live_", "rk_test_",
		"sk_org_",
	}

	word := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
	}
	body := func(c byte) bool {
		return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
	}

	var spans []Span
	for start := range len(src) {
		if start > 0 && word(src[start-1]) {
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

// FuzzStripeSecretKey_matchesReference guards the hand-written scan: the two
// bytes it searches for, the byte it reads in front of a prefix, the order it
// reads the prefixes in, the floor it holds a body to, the alphabet it reads
// that body in and the byte it resumes at may none of them change which keys
// are located.
//
// The seeds spell each prefix once and then the edges the anchor, the floor and
// the byte in front live on — a body one character short, a mode nobody names,
// an organization key read as the shorter of its two prefixes, a key closing a
// word, a key written inside another, the publishable key type this pattern
// declines, and a line that is nothing but anchors. There is no checked-in
// corpus for this target, so what the seeds reach is all a cold run starts
// from.
func FuzzStripeSecretKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("STRIPE_SECRET_KEY=sk_live_0123456789abcdef01234567")
	f.Add("sk_test_0123456789abcdef01234567")
	f.Add("rk_live_0123456789abcdef01234567")
	f.Add("rk_test_0123456789abcdef01234567")
	f.Add("pk_live_0123456789abcdef01234567") // the other half of the format
	f.Add("pk_test_0123456789abcdef01234567")
	f.Add("sk_org_0123456789abcdef01234567")
	f.Add("sk_org_live_0123456789abcdef01234567")
	f.Add("sk_org_test_0123456789abcdef01234567")
	f.Add("sk_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012") // the length Stripe issues today
	f.Add("sk_live_0123456789abcdef0123456")                                                                             // one short of a body
	f.Add("sk_live_0123456789abcdef01234567z")                                                                           // and a run longer than one
	f.Add("sk_live_")                                                                                                    // a prefix with no body at all
	f.Add("sk_0123456789abcdef01234567")                                                                                 // a key type with no mode behind it
	f.Add("sk_prod_0123456789abcdef01234567")                                                                            // a mode no Stripe page names
	f.Add("sk_org_prod_0123456789abcdef01234567")                                                                        // and the same behind the organization scope
	f.Add("SK_LIVE_0123456789abcdef01234567")                                                                            // an uppercase prefix
	f.Add("sk-live-0123456789abcdef01234567")                                                                            // hyphens where the prefix carries underscores
	f.Add("sk_live_0123456789abcdef_01234567")                                                                           // an underscore ends the body
	f.Add("sk_live_0123456789abcdef-01234567")                                                                           // and so does a hyphen
	f.Add("STRIPE_SECRET_KEY_sk_live_0123456789abcdef01234567")                                                          // an underscore in front, which a key is written after
	f.Add("xsk_live_0123456789abcdef01234567")                                                                           // a letter in front, which is a word closing on the prefix
	f.Add("task_test_0123456789abcdef01234567")                                                                          // the snake_case name that word turns away
	f.Add("network_live_0123456789abcdef01234567")
	f.Add("sk_live_0123456789abcdef01234567 rk_live_0123456789abcdef01234567")
	f.Add("sk_live_0123456789abcdef01234567\nrk_test_0123456789abcdef01234567")
	// A key beginning inside the span of the one before it, which a scan
	// resuming past a match steps over.
	f.Add("sk_live_0123456789abcdef01234567rk_test_0123456789abcdef01234567")
	// Candidate positions crowded as close as they can be, with a body behind
	// none of them, and the two bytes the scan searches for on their own.
	f.Add(strings.Repeat("sk_live_", 8))
	f.Add(strings.Repeat("k_", 24))
	f.Add(strings.Repeat("sk_org_", 8) + "0123456789abcdef01234567")
	// The prefix written inside a run of the alphabet, which the byte in front
	// of it turns away, and written after one that ends.
	f.Add("payload=zzzzsk_live_0123456789abcdef01234567zzzz")
	f.Add("payload=zzzz_sk_live_0123456789abcdef01234567zzzz")

	fuzzAgainstReference(f, StripeSecretKey().Find, referenceStripeSecretKeyFind)
}

// stripeSecretKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot
// be.
func stripeSecretKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line carries the two bytes the scan searches for,
	// so what the line times is that search — which is most of what this pattern
	// costs a caller whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="creating a charge" url=https://api.stripe.com/v1/charges `
	key := "sk_live_0123456789abcdef01234567"

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
			src:   strings.Repeat("sk_live_", 128),
			spans: 0,
		},
		{
			// A snake_case name closing on the key type at every candidate,
			// which is the one byte in front turning each of them away before
			// the prefix table is reached at all.
			name:  "words closing on the key type",
			src:   strings.Repeat("task_test_run ", 128),
			spans: 0,
		},
		{
			// Keys crowded as close as a separator lets them be, which is the
			// densest a run of them can be located. What it times is the walk
			// over a body, once per key and no more — the work the scans beside
			// this one keep a run cursor to avoid repeating.
			name:  "keys crowded on one line",
			src:   strings.Repeat(key+" ", 128),
			spans: 128,
		},
		{
			// One key whose body is far longer than any Stripe issues, which is
			// the walk over a run reading to the end of a line and finding a
			// key there.
			name:  "one long body",
			src:   "sk_live_" + strings.Repeat("0123456789abcdef", 256),
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
