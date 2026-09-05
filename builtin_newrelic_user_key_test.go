package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The New Relic user key pattern: what it locates and what it leaves alone,
// written out case by case, and the reference its scan is held to.
//
// What every built-in shares — the convention its name follows, one value per
// accessor, usable spans, no false positive on prose, agreement with the
// reference below, masking that leaves nothing to find out of reach of what it
// redacted, concurrent use and a linear-time scan — is held to in
// builtins_test.go, which drives every built-in from one table rather than a set
// of tests apiece.
//
// The keys written out below are made only of ordered characters: valid in
// shape, obviously not real. A key of the kind New Relic issues today is
// twenty-seven uppercase letters and digits behind its prefix, written here as
// 0123456789ABCDEFGHIJKLMNOPQ; a migrated admin key is twenty-seven hexadecimal
// characters, written as 0123456789abcdef with 0123456789a behind it, and read
// in either case. With the five characters of a prefix that comes to the
// thirty-two characters the rules reading either kind are written to.

const (
	newRelicIssuedKey   = "NRAK-0123456789ABCDEFGHIJKLMNOPQ"
	newRelicMigratedKey = "NRAA-0123456789abcdef0123456789a"
)

func Test_NewRelicUserKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an issued key on its own",
			src:  newRelicIssuedKey,
			want: []Span{{0, 32}},
		},
		{
			name: "a migrated key on its own",
			src:  newRelicMigratedKey,
			want: []Span{{0, 32}},
		},
		{
			name: "an issued key in an environment assignment",
			src:  "NEW_RELIC_API_KEY=" + newRelicIssuedKey,
			want: []Span{{18, 50}},
		},
		{
			name: "a migrated key in an environment assignment",
			src:  "NEW_RELIC_API_KEY=" + newRelicMigratedKey,
			want: []Span{{18, 50}},
		},
		{
			// The count is a floor, so a run carrying on past the
			// twenty-seventh character is redacted to the end of that run.
			name: "an issued run longer than the floor",
			src:  "NRAK-0123456789ABCDEFGHIJKLMNOPQRS",
			want: []Span{{0, 34}},
		},
		{
			name: "a migrated run longer than the floor",
			src:  "NRAA-0123456789abcdef0123456789abcdef",
			want: []Span{{0, 37}},
		},
		{
			// A migrated body is read in hexadecimal of either case, which is
			// what the one rule reading that format reads: it asks for
			// hexadecimal without regard to case, so both are the format and
			// reading only one of them would locate nothing.
			name: "a migrated body written in uppercase hexadecimal",
			src:  "NRAA-0123456789ABCDEF0123456789A",
			want: []Span{{0, 32}},
		},
		{
			// A migrated body is hexadecimal, which is written with no capital
			// past F, so the opening of the next key ends the run and the two
			// spans meet rather than overlap.
			name: "an issued key written against a migrated one",
			src:  newRelicMigratedKey + newRelicIssuedKey,
			want: []Span{{0, 32}, {32, 64}},
		},
		{
			// An issued body is written in an alphabet the opening belongs to,
			// so the run of the key in front carries on into the prefix of the
			// key behind it and stops at that prefix's hyphen.
			name: "an issued key written against another",
			src:  newRelicIssuedKey + newRelicIssuedKey,
			want: []Span{{0, 36}, {32, 64}},
		},
		{
			// The hyphen both prefixes close with is what a migrated body may
			// never carry, so two migrated keys written together do not merge
			// the way two issued ones do: the first body ends at the floor,
			// and the N of the second prefix is not hexadecimal.
			name: "two migrated keys written together",
			src:  newRelicMigratedKey + newRelicMigratedKey,
			want: []Span{{0, 32}, {32, 64}},
		},
		{
			// The far end of the issued alphabet, which no sample or case
			// elsewhere here carries: every published example is drawn from
			// the run 0123456789ABCDEFGHIJKLMNOPQ, so T through Y appear in no
			// issued body anywhere else in this file.
			name: "an issued body drawn from the far end of the alphabet",
			src:  "NRAK-STUVWXYZ0123456789ABCDEFGHI",
			want: []Span{{0, 32}},
		},
		{
			// The far end of the migrated alphabet, the mirror image of the
			// case above.
			name: "a migrated body drawn from the far end of the alphabet",
			src:  "NRAA-fedcba9876543210fedcba98765",
			want: []Span{{0, 32}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NewRelicUserKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NewRelicUserKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "the issued prefix alone",
			src:  "NRAK-",
		},
		{
			name: "the migrated prefix alone",
			src:  "NRAA-",
		},
		{
			name: "an issued body one character short of the floor",
			src:  "NRAK-0123456789ABCDEFGHIJKLMNOP",
		},
		{
			name: "a migrated body one character short of the floor",
			src:  "NRAA-0123456789abcdef0123456789",
		},
		{
			// An issued body is read in uppercase alone, which is the case the
			// one rule dividing on it reads this kind in: a lowercase letter
			// ends the run where it stands.
			name: "an issued body in lowercase",
			src:  "NRAK-0123456789abcdefghijklmnopq",
		},
		{
			// The alphabets do not meet: a migrated body is hexadecimal, so the
			// letters an issued body carries past F end it.
			name: "an issued body behind the migrated prefix",
			src:  "NRAA-0123456789ABCDEFGHIJKLMNOPQ",
		},
		{
			name: "a body carrying a lowercase letter",
			src:  "NRAK-0123456789ABCDEFGHIJKLMnOPQ",
		},
		{
			name: "a body broken by a space",
			src:  "NRAK-0123456789ABCDEF GHIJKLMNOPQ",
		},
		{
			// The character both prefixes close with, which is the one the
			// whole scan rests on a body not carrying.
			name: "a body broken by a hyphen",
			src:  "NRAK-0123456789ABCDEF-GHIJKLMNOPQ",
		},
		{
			name: "a body broken by an underscore",
			src:  "NRAK-0123456789ABCDEF_GHIJKLMNOPQ",
		},
		{
			name: "a body broken by a dot",
			src:  "NRAK-0123456789ABCDEF.GHIJKLMNOPQ",
		},
		{
			// The prefixes are read in the one case New Relic writes them.
			name: "a lowercase prefix",
			src:  "nrak-0123456789ABCDEFGHIJKLMNOPQ",
		},
		{
			name: "the prefix without its hyphen",
			src:  "NRAK0123456789ABCDEFGHIJKLMNOPQR",
		},
		{
			name: "an underscore where the prefix closes",
			src:  "NRAK_0123456789ABCDEFGHIJKLMNOPQ",
		},
		{
			name: "the opening with no character naming a kind",
			src:  "NRA-0123456789ABCDEFGHIJKLMNOPQR",
		},
		{
			name: "a kind character no user key carries",
			src:  "NRAX-0123456789ABCDEFGHIJKLMNOPQ",
		},
		{
			// New Relic's license key, which carries no prefix and closes on
			// the four characters NRAL instead. The L stands where a kind
			// would, and nothing follows it that a prefix closes with.
			name: "a license key",
			src:  "license_key=0123456789abcdef0123456789abcdef0123NRAL",
		},
		{
			// The other credentials New Relic writes with a prefix of their
			// own: the browser key it embeds in a page, and the two Insights
			// keys. None of them opens with the three characters this scan
			// reads a candidate back from.
			name: "an ingest browser key",
			src:  "NRJS-0123456789abcdef0123456789a",
		},
		{
			name: "an insights insert key",
			src:  "NRII-0123456789abcdef0123456789abcdef01",
		},
		{
			name: "an insights query key",
			src:  "NRIQ-0123456789abcdef0123456789abcdef01",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="querying nerdgraph" url=https://api.newrelic.com/graphql`,
		},
		{
			name: "a new relic environment variable holding a host name",
			src:  "NEW_RELIC_HOST=https://api.newrelic.com",
		},
		{
			// The four characters that end a run, tested inside a migrated
			// body rather than an issued one: a body broken by any of them is
			// too short to be one, whichever floor it runs up against.
			name: "a migrated body broken by a space",
			src:  "NRAA-0123456789abcdef 0123456789a",
		},
		{
			name: "a migrated body broken by a hyphen",
			src:  "NRAA-0123456789abcdef-0123456789a",
		},
		{
			name: "a migrated body broken by an underscore",
			src:  "NRAA-0123456789abcdef_0123456789a",
		},
		{
			name: "a migrated body broken by a dot",
			src:  "NRAA-0123456789abcdef.0123456789a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NewRelicUserKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_NewRelicUserKey_inContext(t *testing.T) {
	// The places a key is written, which are the places New Relic's own
	// documentation puts one: the environment its CLI and its client libraries
	// read it from, the argument the Terraform provider takes it as, the
	// Api-Key header a NerdGraph request carries it in and the command line a
	// curl example writes that header on.
	key := newRelicIssuedKey

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key in a dotenv line",
			src:  "NEW_RELIC_API_KEY=" + key,
			want: []Span{{18, 18 + len(key)}},
		},
		{
			name: "a key in a terraform provider block",
			src:  `api_key = "` + key + `"`,
			want: []Span{{11, 11 + len(key)}},
		},
		{
			name: "a key in the header nerdgraph is called with",
			src:  "Api-Key: " + key,
			want: []Span{{9, 9 + len(key)}},
		},
		{
			name: "a key on a command line",
			src:  `curl -X POST -H "Api-Key: ` + key + `" https://api.newrelic.com/graphql`,
			want: []Span{{26, 26 + len(key)}},
		},
		{
			name: "a key in json",
			src:  `{"apiKey":"` + key + `"}`,
			want: []Span{{11, 11 + len(key)}},
		},
		{
			name: "a key at the end of a sentence",
			src:  "the key is " + key + ".",
			want: []Span{{11, 11 + len(key)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NewRelicUserKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NewRelicUserKey_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a key is written
	// against a word character. One behind would drop rather than trim as well,
	// and where it were asked decides what it drops. Asked behind the count, it
	// drops the key a letter, a digit or an underscore is written against. Asked
	// behind that run, it drops the key a word character that alphabet leaves out
	// is written against — a lowercase letter behind an issued key, a letter past
	// f behind a migrated one, an underscore behind either.
	key := newRelicIssuedKey

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key after an underscore",
			src:  "NEW_RELIC_API_KEY_" + key,
			want: []Span{{18, 18 + len(key)}},
		},
		{
			name: "a key after a lowercase letter",
			src:  "x" + key,
			want: []Span{{1, 1 + len(key)}},
		},
		{
			name: "a word written against a key",
			src:  key + "suffix",
			want: []Span{{0, len(key)}},
		},
		{
			name: "a hyphenated word written against a key",
			src:  key + "-suffix",
			want: []Span{{0, len(key)}},
		},
		{
			// The floor read to the end of the run: capitals written against a
			// key carry the span past the key rather than ending it.
			name: "capitals written against a key",
			src:  key + "ZZZ",
			want: []Span{{0, len(key) + 3}},
		},
		{
			// The mirror of that for a migrated key: a lowercase letter past f
			// is a word character the alphabet leaves out, so it ends the run
			// exactly where it stands rather than carrying the span on.
			name: "a lowercase suffix written against a migrated key",
			src:  newRelicMigratedKey + "suffix",
			want: []Span{{0, len(newRelicMigratedKey)}},
		},
		{
			// Capitals past F are outside the migrated alphabet as well, so
			// they end the run rather than carrying it on the way they do for
			// an issued key.
			name: "capitals outside hexadecimal written against a migrated key",
			src:  newRelicMigratedKey + "ZZZ",
			want: []Span{{0, len(newRelicMigratedKey)}},
		},
		{
			// Where the run carrying on is itself hexadecimal, it is read as
			// part of the same body and the span reaches its end, the same as
			// the issued case above.
			name: "a migrated run longer than the floor written against the key",
			src:  newRelicMigratedKey + "abc",
			want: []Span{{0, len(newRelicMigratedKey) + 3}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NewRelicUserKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NewRelicUserKey_aKeyInsideAKey(t *testing.T) {
	// A key can be written inside another, which is why the scan resumes a byte
	// past the start of a candidate rather than past the candidate. It is the
	// issued kind that reaches this: an issued body is written in the alphabet
	// the opening and both kind characters belong to, so such a body may close
	// with a whole opening and a kind, and the hyphen of the next key stand
	// directly behind it. A migrated body is hexadecimal and carries no capital
	// an opening needs, so no key begins inside one.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			// An issued body closing on NRAK, with the hyphen that reads it
			// back written after the body that key ends.
			name: "an issued key beginning at the end of another",
			src:  "NRAK-0123456789ABCDEFGHIJKLMNRAK-0123456789ABCDEFGHIJKLMNOPQ",
			want: []Span{{0, 32}, {28, 60}},
		},
		{
			// The same opening with nothing behind it long enough to be a body,
			// so the key in front of it is the one there is.
			name: "an opening at the end of a key that opens no key",
			src:  "NRAK-0123456789ABCDEFGHIJKLMNRAK-0123456789",
			want: []Span{{0, 32}},
		},
		{
			// A migrated key beginning where an issued body closes on NRAA. The
			// issued body ends at that key's hyphen and the migrated one is read
			// in hexadecimal from behind it.
			name: "a migrated key beginning at the end of an issued one",
			src:  "NRAK-0123456789ABCDEFGHIJKLMNRAA-0123456789abcdef0123456789a",
			want: []Span{{0, 32}, {28, 60}},
		},
		{
			name: "a prefix in front of a key",
			src:  "NRAK-" + newRelicIssuedKey,
			want: []Span{{5, 37}},
		},
		{
			// The opening written where a body would have to hold it, with no
			// hyphen behind the character naming a kind, so the candidate it
			// opens ends there and the key is the one the prefix behind it
			// opens.
			name: "an opening written inside a body",
			src:  "NRAK-01234NRAK-0123456789ABCDEFGHIJKLMNOPQ",
			want: []Span{{10, 42}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NewRelicUserKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_NewRelicUserKey_cutShortOfTheFloor(t *testing.T) {
	// What reading the count as a floor costs, kept as a decision on the
	// record. A line cut to a column limit partway through a key leaves a
	// prefix and a body too short to be one, and nothing is located: the
	// characters written before the cut stay in the output. The whole key is
	// what the same text carries when it is not cut.
	const cut = "NRAK-0123456789ABCDEFGHIJ"

	if got, _ := NewRelicUserKey().Find(cut); len(got) != 0 {
		t.Errorf("Find(%q) = %v, want no span", cut, got)
	}
	if got, _ := NewRelicUserKey().Find(newRelicIssuedKey); !slices.Equal(got, []Span{{0, 32}}) {
		t.Errorf("Find(%q) = %v, want the whole key", newRelicIssuedKey, got)
	}
}

func Test_NewRelicUserKey_holdsAKeyTheInputCutShort(t *testing.T) {
	// What Find's second return settles. builtin_scan.go and the rationale in
	// builtin_newrelic_user_key.go give two shapes: a piece of a prefix
	// standing at the end of the input, and a candidate the end of the input
	// cut short. Everything else is settled to the end of the input, since
	// nothing there could still become a key.
	tests := []struct {
		name   string
		src    string
		retain int
	}{
		{
			// No prefix and no piece of one anywhere in the text, so the whole
			// of it is settled.
			name:   "no credential at all",
			src:    "there is no credential in this sentence",
			retain: len("there is no credential in this sentence"),
		},
		{
			// The three letters shared by both prefixes stand at the end of
			// the input, so what comes next could still complete either one:
			// the text from there on is held.
			name:   "a piece of the opening at the end of the input",
			src:    "xxx NRA",
			retain: 4,
		},
		{
			// A candidate whose body has not reached the floor, with the run
			// carrying on to the end of the input. What comes next either
			// carries the run on to a key or ends it, so this candidate's
			// start is held rather than settled.
			name:   "a candidate the input cut short of the floor",
			src:    "xxx NRAK-0123456789ABCDE",
			retain: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, retain := NewRelicUserKey().Find(tt.src); retain != tt.retain {
				t.Errorf("Find(%q) retain = %d, want %d", tt.src, retain, tt.retain)
			}
		})
	}
}

func Test_NewRelicUserKey_theShapesWrittenByAccident(t *testing.T) {
	// The shapes text reaches this format by. base64url is the one alphabet in
	// ordinary use carrying the hyphen, so a payload written in it can hold a
	// whole prefix where hexadecimal and standard base64 hold none; what such a
	// payload then has to carry is twenty-seven characters the kind's own
	// alphabet admits, which for the issued kind means twenty-seven of a single
	// case. A digest is the other: hexadecimal written behind the migrated
	// prefix is that kind's format exactly, in either case it is written in.
	// Where either shape is written there is nothing left in the text to tell it
	// from a key.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "the issued prefix inside a longer base64url run",
			src:  "payload=zzzzNRAK-0123456789ABCDEFGHIJKLMNOPQzzzz",
			want: []Span{{12, 44}},
		},
		{
			// The same run written in both cases, which is what a base64url
			// payload ordinarily is: the body ends at the first character of
			// the other case, far short of the floor.
			name: "a base64url run written in both cases",
			src:  "payload=zzzzNRAK-0123456789ABCDefghijklmnopqzzzz",
			want: nil,
		},
		{
			name: "the prefix where a signature stands",
			src:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.NRAA-0123456789abcdef0123456789a",
			want: []Span{{40, 72}},
		},
		{
			// Standard base64 writes the plus and the slash where base64url
			// writes the hyphen and the underscore, so a payload written in it
			// holds no character a prefix closes with however long it runs.
			name: "a standard base64 payload, which carries no hyphen",
			src:  "payload=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEANRAK0123456789ABCDEFGHIJKLMNOPQ",
			want: nil,
		},
		{
			// A SHA-1 is forty lowercase hexadecimal characters, which is a
			// migrated body's alphabet exactly, so one written behind that
			// prefix is redacted to the end of the digest.
			name: "a sha-1 behind the migrated prefix",
			src:  "NRAA-0123456789abcdef0123456789abcdef01234567",
			want: []Span{{0, 45}},
		},
		{
			// The same digest written in capitals, which is hexadecimal of the
			// other case and is a migrated body just as the first is.
			name: "an uppercase sha-1 behind the migrated prefix",
			src:  "NRAA-0123456789ABCDEF0123456789ABCDEF01234567",
			want: []Span{{0, 45}},
		},
		{
			// The same digest behind the issued prefix, which reads no
			// lowercase: the body ends at the first letter of it.
			name: "a sha-1 behind the issued prefix",
			src:  "NRAK-0123456789abcdef0123456789abcdef01234567",
			want: nil,
		},
		{
			// A screaming snake case name reaches the opening and the kind, and
			// is turned away by the underscore standing where the hyphen must.
			name: "a screaming snake case name opening with the prefix",
			src:  "NRAK_TOKEN_0123456789ABCDEFGHIJKLMNOPQ",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := NewRelicUserKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_newRelicUserKeyPrefixes(t *testing.T) {
	// The prefixes are built from the opening, the kinds and the separator
	// rather than written out, so what is held here is what the scan takes for
	// granted about the parts. Every prefix is the same length, since a
	// candidate is read back from an anchor standing at one index of all of
	// them; every character but the last belongs to the alphabet an issued body
	// is written in, which is what lets a key begin inside another; and the last
	// belongs to neither alphabet, which the linearity below rests on.
	if got, want := len(newRelicUserKeyPrefixes), len(newRelicUserKeyKinds); got != want {
		t.Fatalf("%d prefix(es) built from %d kind(s)", got, want)
	}
	for _, p := range newRelicUserKeyPrefixes {
		if want := len(newRelicUserKeyOpening) + 2; len(p) != want {
			t.Errorf("prefix %q is %d characters, want %d", p, len(p), want)
		}
		if !strings.HasPrefix(p, newRelicUserKeyOpening) {
			t.Errorf("prefix %q does not open with %q", p, newRelicUserKeyOpening)
		}
		if c := p[len(p)-1]; c != newRelicUserKeySeparator {
			t.Errorf("prefix %q closes with %q, want the separator %q", p, c, byte(newRelicUserKeySeparator))
		}
		for i := range len(p) - 1 {
			if !isNewRelicUserKeyIssuedByte(p[i]) {
				t.Errorf("prefix %q carries %q at index %d, which an issued body may not be written with", p, p[i], i)
			}
		}
	}
}

func Test_newRelicUserKeyPrefixes_runsDoNotOverlap(t *testing.T) {
	// The scan walks the run behind every candidate and keeps no cursor over it,
	// where a scan whose prefix closes on a character its own body admits has to
	// keep one. What makes the cursor unnecessary is that two candidates can
	// never read the same run: a candidate asks for the separator directly in
	// front of its body, no body of either kind may be written with it, so the
	// run of an earlier candidate has already ended there and the later
	// candidate's run begins past it. Were that character one a body admits, a
	// run dense in prefixes would be walked once for every candidate in it and
	// the scan would cost time quadratic in the length of such a line.
	if isNewRelicUserKeyIssuedByte(newRelicUserKeySeparator) {
		t.Errorf("the separator %q is a character an issued body may be written with", byte(newRelicUserKeySeparator))
	}
	if isNewRelicUserKeyMigratedByte(newRelicUserKeySeparator) {
		t.Errorf("the separator %q is a character a migrated body may be written with", byte(newRelicUserKeySeparator))
	}
}

func Test_newRelicUserKeyAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a candidate
	// back from, in every prefix. A prefix or an index changed without the other
	// leaves the scan opening candidates nowhere near where a key begins, and
	// what such a scan finds is nothing at all rather than something wrong.
	for _, p := range newRelicUserKeyPrefixes {
		if newRelicUserKeyAnchorIndex >= len(p) {
			t.Fatalf("the anchor stands at %d, the prefix %q is %d characters", newRelicUserKeyAnchorIndex, p, len(p))
		}
		if c := p[newRelicUserKeyAnchorIndex]; c != newRelicUserKeyAnchor {
			t.Errorf("prefix %q carries %q where the scan searches for %q, so no candidate is ever found at it",
				p, c, byte(newRelicUserKeyAnchor))
		}

		// What the anchor costs, counted rather than claimed in prose: it
		// stands once in a prefix, so a line of keys stops the search once a
		// key rather than twice.
		if n := strings.Count(p, string(rune(newRelicUserKeyAnchor))); n != 1 {
			t.Errorf("the anchor stands %d times in %q, want 1", n, p)
		}
	}
}

func Test_newRelicUserKeyKinds_areTheKindsTheScanReads(t *testing.T) {
	// The kinds the table names are the kinds the scan reads, and no others.
	// The table is what the prefixes and the tail are built from, so a kind
	// listed there and not read is a stream holding text back for a key that is
	// never found, and a kind read and not listed is a stream releasing the
	// characters a key opens with.
	//
	// It is driven through Find rather than read off the table, since what the
	// scan does with a kind is the thing in question. Each kind is offered a
	// body of both alphabets, so the answer says which alphabet it was read in
	// as well as whether it was read at all.
	const (
		issuedBody   = "0123456789ABCDEFGHIJKLMNOPQ"
		migratedBody = "0123456789abcdef0123456789a"
	)

	for c := range 256 {
		// The kind is written as the one byte it is. string(rune(c)) would
		// encode everything from 128 up as two bytes, which no candidate reads
		// as a kind at all, and the half of this loop above 127 would then pass
		// without ever asking the scan the question.
		prefix := newRelicUserKeyOpening + string([]byte{byte(c)}) + string(rune(newRelicUserKeySeparator))
		for _, body := range []struct {
			name string
			text string
			kind byte
		}{
			{"an issued body", issuedBody, newRelicUserKeyIssuedKind},
			{"a migrated body", migratedBody, newRelicUserKeyMigratedKind},
		} {
			got, _ := NewRelicUserKey().Find(prefix + body.text)
			located, want := len(got) != 0, byte(c) == body.kind
			if located != want {
				t.Errorf("Find(%q) = %v, %s behind the kind %q", prefix+body.text, got, body.name, byte(c))
			}
		}
	}
}

func Test_newRelicUserKeyChars(t *testing.T) {
	// The parts a prefix is built from, and the count a body of either kind is
	// held to. New Relic writes none of the second down; this is the count every
	// rule reading either kind is written to, and the scan reads it as a floor.
	if got := newRelicUserKeyOpening; got != "NRA" {
		t.Errorf("newRelicUserKeyOpening = %q, want %q", got, "NRA")
	}
	if got := byte(newRelicUserKeySeparator); got != '-' {
		t.Errorf("newRelicUserKeySeparator = %q, want %q", got, byte('-'))
	}
	if got := byte(newRelicUserKeyIssuedKind); got != 'K' {
		t.Errorf("newRelicUserKeyIssuedKind = %q, want %q", got, byte('K'))
	}
	if got := byte(newRelicUserKeyMigratedKind); got != 'A' {
		t.Errorf("newRelicUserKeyMigratedKind = %q, want %q", got, byte('A'))
	}
	if got := newRelicUserKeyBodyChars; got != 27 {
		t.Errorf("newRelicUserKeyBodyChars = %d, want 27", got)
	}
}

func Test_NewRelicUserKey_scanIsLinear(t *testing.T) {
	// A line dense in prefixes holds a candidate for every five characters it
	// has. The one thing a candidate reads that is a walk over the rest of the
	// input rather than a bounded test is where its run ends, and repeating that
	// walk at every candidate would cost time quadratic in the length of the
	// line. The bound here is far above a linear scan and far below a quadratic
	// one.
	//
	// The generic guard in builtins_test.go repeats the samples, which hold a
	// candidate every twenty-eight bytes where they are densest, because a
	// sample has to carry a whole body to be one. The crowding a line can
	// actually carry, a candidate every five bytes, stays here.
	sources := map[string]string{
		// Candidates as close together as a prefix allows, none of them with a
		// run long enough to be a body: every one reaches the body of the loop
		// and every one is rejected.
		"a candidate every five characters": strings.Repeat("NRAK-", 200000),
		// Keys written into one another, each beginning four characters before
		// the one in front of it ends, so every candidate is a key and every one
		// of them walks a run.
		"a key beginning inside every key": strings.Repeat("NRAK-0123456789ABCDEFGHIJKLM", 35000),
		// One candidate whose body is the whole line, which is the walk over a
		// run reading the length of the input and finding a key.
		"a body that runs the length of the line": "NRAK-" + strings.Repeat("A", 1800000),
		// An anchor every other byte with nothing in front of it that opens a
		// prefix, which is the cheapest way a position is declined: one byte
		// read and the candidate gone.
		"an anchor that opens no candidate": strings.Repeat("xR", 900000),
		// And the letters of an opening with no anchor among them, which is the
		// walk reading a whole line and stopping nowhere in it.
		"the letters of a prefix with no anchor": strings.Repeat("NAK-", 450000),
	}

	checkScanIsLinear(t, NewRelicUserKey(), sources)
}

// referenceNewRelicUserKey is the expression the scan in
// builtin_newrelic_user_key.go reads by hand: the statement of what a New Relic
// user key is, kept here so that the scan can be held to it.
//
// The prefixes, the floor and the two alphabets are spelled again rather than
// built from newRelicUserKeyPrefixes, newRelicUserKeyBodyChars and the byte
// tests beside them. A reference sharing those declarations could not disagree
// with the scan about them, and it is exactly that disagreement the fuzz target
// below is for: the two have to be changed together or reported apart.
//
// The floor is written as a counted repetition, which is what a reference is
// otherwise written out by hand to avoid. It costs nothing here, and for the
// reason the scan needs no cursor: candidates cannot crowd inside one run, so no
// input makes an engine walk the same run more than once. Both branches open on
// a literal an engine can search the text for, and the two share their first
// three characters, so there is one literal in front of the grammar rather than
// an alternation of literals to walk a machine at every byte for.
var referenceNewRelicUserKey = regexp.MustCompile(`NRAK-[0-9A-Z]{27,}|NRAA-[0-9a-fA-F]{27,}`)

// referenceNewRelicUserKeyFind locates keys the plain way: the leftmost match of
// the expression above, then the leftmost one beginning after that match's first
// byte, over and over, with nothing remembered between them.
//
// FindAllStringIndex would be the shorter way to write this and the wrong one.
// It resumes past a match, and a key can begin inside one: the characters an
// opening and a kind are written with belong to the alphabet an issued body is,
// so such a body closing with NRAK or NRAA holds the start of the key behind it.
// The scan finds both and reports the two spans overlapping for a Masker to
// resolve, so the reference must ask about both.
func referenceNewRelicUserKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceNewRelicUserKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzNewRelicUserKey_matchesReference guards the hand-written scan: the
// openings it searches for, the kinds it reads between them and the separator,
// the case it reads all of those in, the floor it holds a body to, the two
// alphabets it reads a body in and the byte it resumes at may none of them
// change which keys are located.
func FuzzNewRelicUserKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("NEW_RELIC_API_KEY=NRAK-0123456789ABCDEFGHIJKLMNOPQ")
	f.Add("NRAA-0123456789abcdef0123456789a")
	f.Add("NRAK-0123456789ABCDEFGHIJKLMNOP") // an issued body one short of the floor
	f.Add("NRAA-0123456789abcdef0123456789") // and a migrated one
	f.Add("NRAK-0123456789ABCDEFGHIJKLMNOPQRS")
	f.Add("NRAK-0123456789abcdefghijklmnopq") // an issued body in lowercase
	f.Add("NRAA-0123456789ABCDEF0123456789A") // a migrated body in uppercase hexadecimal
	f.Add("NRAA-0123456789aBcDeF0123456789A") // and in both cases at once
	f.Add("NRAA-0123456789ABCDEFGHIJKLMNOPQ") // an issued body behind the migrated prefix
	f.Add("NRAK-0123456789ABCDEF GHIJKLMNOPQ")
	f.Add("NRAK-0123456789ABCDEF-GHIJKLMNOPQ")
	f.Add("NRAK-0123456789ABCDEF_GHIJKLMNOPQ")
	f.Add("NRAK-0123456789ABCDEF\nGHIJKLMNOPQ")
	f.Add("nrak-0123456789ABCDEFGHIJKLMNOPQ") // a lowercase prefix
	f.Add("NRAK0123456789ABCDEFGHIJKLMNOPQR") // the prefix without its hyphen
	f.Add("NRAK_0123456789ABCDEFGHIJKLMNOPQ") // an underscore where it closes
	f.Add("NRA-0123456789ABCDEFGHIJKLMNOPQR") // the opening with no kind
	f.Add("NRAX-0123456789ABCDEFGHIJKLMNOPQ") // a kind no user key carries
	f.Add("xNRAK-0123456789ABCDEFGHIJKLMNOPQ")
	// The other credentials New Relic writes, which this pattern locates
	// nothing in: the license key that closes on NRAL, the browser key and the
	// two Insights keys.
	f.Add("license_key=0123456789abcdef0123456789abcdef0123NRAL")
	f.Add("NRJS-0123456789abcdef0123456789a")
	f.Add("NRII-0123456789abcdef0123456789abcdef01")
	f.Add("NRIQ-0123456789abcdef0123456789abcdef01")
	// A digest behind either prefix, and a prefix inside base64url text, which
	// is the alphabet that can hold one.
	f.Add("NRAA-0123456789abcdef0123456789abcdef01234567")
	f.Add("NRAK-0123456789abcdef0123456789abcdef01234567")
	f.Add("NRAA-0123456789ABCDEF0123456789ABCDEF01234567")
	f.Add("payload=zzzzNRAK-0123456789ABCDEFGHIJKLMNOPQzzzz")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.NRAA-0123456789abcdef0123456789a")
	// A prefix in front of a key, keys with nothing between them, and a key
	// beginning at the end of another, which a scan resuming past a match would
	// lose.
	f.Add("NRAK-NRAK-0123456789ABCDEFGHIJKLMNOPQ")
	f.Add("NRAK-01234NRAK-0123456789ABCDEFGHIJKLMNOPQ")
	f.Add("NRAK-0123456789ABCDEFGHIJKLMNOPQNRAK-0123456789ABCDEFGHIJKLMNOPQ")
	f.Add("NRAA-0123456789abcdef0123456789aNRAK-0123456789ABCDEFGHIJKLMNOPQ")
	f.Add("NRAK-0123456789ABCDEFGHIJKLMNRAK-0123456789ABCDEFGHIJKLMNOPQ")
	f.Add("NRAK-0123456789ABCDEFGHIJKLMNRAA-0123456789abcdef0123456789a")
	f.Add(strings.Repeat("NRAK-", 64))
	f.Add(strings.Repeat("NRAK-", 64) + "0123456789ABCDEFGHIJKLMNOPQ")
	f.Add(strings.Repeat("NRAK-0123456789ABCDEFGHIJKLM", 8))
	f.Add(strings.Repeat("-", 128))
	f.Add(strings.Repeat("R", 128))
	f.Add(strings.Repeat("NRA", 128))

	fuzzAgainstReference(f, NewRelicUserKey().Find, referenceNewRelicUserKeyFind)
}

// newRelicUserKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func newRelicUserKeyFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the hyphen the prefixes close with
	// stands twice on it, in the date alone, where no capital of an opening
	// stands at all. What the line times is the search for the anchor, which is
	// most of what this pattern costs a caller whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="querying nerdgraph" url=https://api.newrelic.com/graphql `
	key := newRelicIssuedKey

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A prefix is five characters carrying the anchor once, so a run of
			// them stops the search once every five characters and each stop
			// reads a body of four characters, which is the opening of the
			// prefix behind it and far short of the floor.
			name:  "candidates that are not values",
			src:   strings.Repeat("NRAK-", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads an opening, which is the cheapest a
			// candidate is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("R", 4096),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the right alphabet up
			// to its last character, so the whole of a candidate is walked
			// before it is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("NRAK-0123456789ABCDEFGHIJKLMNOP. ", 16),
			spans: 0,
		},
		{
			// A run of the alphabet an issued body is read in, carrying no
			// anchor at all, which is what the search walks a digest of.
			name:  "a run of the body alphabet",
			src:   strings.Repeat("0123456789ABCDEF", 256),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "api_key=" + key,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "api_key=" + key,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"api_key="+key+"\n", 32),
			spans: 32,
		},
	}
}
