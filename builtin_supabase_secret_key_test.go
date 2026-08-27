package mask

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The Supabase secret key pattern: what it locates and what it leaves alone,
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
// shape, obviously not real. The random part is 0123456789abcdef written once
// and then as far as 5, which is the twenty-two characters the generator slices,
// and the checksum behind the separator is the first eight of the same run. With
// the prefix in front a key comes to forty-one characters.

func Test_SupabaseSecretKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key on its own",
			src:  "sb_secret_0123456789abcdef012345_01234567",
			want: []Span{{0, 41}},
		},
		{
			name: "a key in an environment assignment",
			src:  "SUPABASE_SECRET_KEY=sb_secret_0123456789abcdef012345_01234567",
			want: []Span{{20, 61}},
		},
		{
			// The count is read exactly, so what follows the forty-first
			// character is not part of the key and stays in the text.
			name: "a run longer than the count is a key and what follows it",
			src:  "sb_secret_0123456789abcdef012345_012345678",
			want: []Span{{0, 41}},
		},
		{
			name: "two keys with nothing between them",
			src:  "sb_secret_0123456789abcdef012345_01234567sb_secret_0123456789abcdef012345_01234567",
			want: []Span{{0, 41}, {41, 82}},
		},
		{
			// The candidate this scan resumes a byte along for. The prefix at
			// the front of the input opens a candidate whose body would carry
			// its separator eleven characters early; the key is the one
			// standing ten characters in, and a scan stepping over what it
			// declined would never reach it.
			name: "a prefix in front of a key",
			src:  "sb_secret_sb_secret_0123456789abcdef012345_01234567",
			want: []Span{{10, 51}},
		},
		{
			// base64url holds the hyphen, which the key the vendor's own
			// tooling writes into a local stack carries.
			name: "a hyphen in the random part",
			src:  "sb_secret_0123456789-bcdef012345_01234567",
			want: []Span{{0, 41}},
		},
		{
			name: "a hyphen in the checksum",
			src:  "sb_secret_0123456789abcdef012345_0123456-",
			want: []Span{{0, 41}},
		},
		{
			name: "an uppercase body",
			src:  "sb_secret_0123456789ABCDEF012345_01234567",
			want: []Span{{0, 41}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabaseSecretKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabaseSecretKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prefix alone",
			src:  "sb_secret_",
		},
		{
			// Thirty where the grammar asks for thirty-one, which is the
			// shape of one of the false positives betterleaks ships against
			// this prefix.
			name: "a body one character short",
			src:  "sb_secret_0123456789abcdef012345_0123456",
		},
		{
			// The separator is the character the generator writes and the count
			// either side of it is what divides the parts, so a body of the
			// right length with the separator a character early is no key.
			name: "the separator one character early",
			src:  "sb_secret_0123456789abcdef01234_501234567",
		},
		{
			name: "the separator one character late",
			src:  "sb_secret_0123456789abcdef0123450_1234567",
		},
		{
			// The one position the separator pins. Every other character of a
			// body may be an underscore, so what fails here is the character
			// twenty-three behind the prefix and nothing else.
			name: "a body of the right length with no separator",
			src:  "sb_secret_0123456789abcdef012345001234567",
		},
		{
			name: "a character outside the alphabet in the random part",
			src:  "sb_secret_0123456789.bcdef012345_01234567",
		},
		{
			name: "a character outside the alphabet in the checksum",
			src:  "sb_secret_0123456789abcdef012345_0123456.",
		},
		{
			name: "a body broken by a space",
			src:  "sb_secret_0123456789 bcdef012345_01234567",
		},
		{
			name: "an uppercase prefix",
			src:  "SB_SECRET_0123456789abcdef012345_01234567",
		},
		{
			name: "a hyphen where the prefix carries its closing underscore",
			src:  "sb_secret-0123456789abcdef012345_01234567",
		},
		{
			name: "the prefix without its closing underscore",
			src:  "sb_secret0123456789abcdef012345_01234567",
		},
		{
			name: "the publishable prefix",
			src:  "sb_publishable_0123456789abcdef012345_01234567",
		},
		{
			name: "a body of the right shape opening with no prefix",
			src:  "xxxxxxxxxx0123456789abcdef012345_01234567",
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a log line",
			src:  `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.supabase.co/rest/v1/todos`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabaseSecretKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_SupabaseSecretKey_inContext(t *testing.T) {
	// The places a secret key is written. It never reaches a browser, so what
	// carries one is a server's configuration, the header a server-side request
	// sends and the response the Management API first reveals one in.
	const key = "sb_secret_0123456789abcdef012345_01234567"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key in a dotenv line",
			src:  "SUPABASE_SECRET_KEY=" + key,
			want: []Span{{20, 20 + len(key)}},
		},
		{
			name: "a key in an apikey header",
			src:  "apikey: " + key,
			want: []Span{{8, 8 + len(key)}},
		},
		{
			name: "a key in a bearer token header",
			src:  "Authorization: Bearer " + key,
			want: []Span{{22, 22 + len(key)}},
		},
		{
			name: "a key in the response that reveals it",
			src:  `{"api_key":"` + key + `","type":"secret"}`,
			want: []Span{{12, 12 + len(key)}},
		},
		{
			name: "a key in a client constructor",
			src:  `createClient(url, "` + key + `")`,
			want: []Span{{19, 19 + len(key)}},
		},
		{
			name: "a key at the end of a sentence",
			src:  "the key is " + key + ".",
			want: []Span{{11, 11 + len(key)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabaseSecretKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabaseSecretKey_nextToWordCharacters(t *testing.T) {
	// There is no boundary on either side of a match. A word boundary in front
	// would drop the whole match rather than trim it wherever a key is written
	// against a word character, and one behind it would drop a key followed by
	// a base64url character — which the last two cases are.
	const key = "sb_secret_0123456789abcdef012345_01234567"

	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key after an underscore",
			src:  "SUPABASE_KEY_" + key,
			want: []Span{{13, 13 + len(key)}},
		},
		{
			name: "a key after a letter",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabaseSecretKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabaseSecretKey_underscoresInTheRandomPart(t *testing.T) {
	// The random part is sliced out of a base64url encoding, so it carries
	// underscores of its own — the vendor's own examples include one that does.
	// That is what separates this separator from one standing between parts
	// written in an alphabet it is not in: it settles nothing about where the
	// parts divide, and only the count does. So a body carrying underscores
	// anywhere but the twenty-third character is a key all the same, and a body
	// carrying none there is not, however many it carries elsewhere.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "an underscore in the random part",
			src:  "sb_secret_0123456789_bcdef012345_01234567",
			want: []Span{{0, 41}},
		},
		{
			name: "an underscore in the checksum",
			src:  "sb_secret_0123456789abcdef012345_0123456_",
			want: []Span{{0, 41}},
		},
		{
			// What the separator still rules out where underscores are
			// everywhere else: the character it stands at is the one position
			// of a body that may be nothing else.
			name: "a hyphen where the separator stands and underscores around it",
			src:  "sb_secret_______________________-________",
		},
		{
			name: "a body of underscores alone",
			src:  "sb_secret________________________________",
			want: []Span{{0, 41}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabaseSecretKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabaseSecretKey_aKeyInsideAKey(t *testing.T) {
	// A key can be written inside another, which is why the scan resumes a byte
	// past the start of a candidate rather than past the candidate. The
	// alphabet a body is drawn from holds every character the prefix is written
	// with, so a body may spell the prefix and open a candidate that reads on
	// past the end of the key it stands in. The spans overlap where it does,
	// which Masker.locate resolves.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a key beginning inside another",
			src:  "sb_secret_sb_secret_0123456789ab_012345670_01234567",
			want: []Span{{0, 41}, {10, 51}},
		},
		{
			// The prefix inside the body without the length behind it to reach
			// a key of its own.
			name: "a prefix inside a body that opens no key",
			src:  "sb_secret_sb_secret_0123456789ab_01234567",
			want: []Span{{0, 41}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabaseSecretKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_SupabaseSecretKey_aBase64URLRunBehindThePrefix(t *testing.T) {
	// The collision this format leaves. Thirty-one characters of base64url with
	// an underscore twenty-three characters in is the vendor's format exactly,
	// so nothing is left in the text to tell such a run from a key and
	// declining it would decline every key Supabase issues.
	//
	// What has to be written to reach it is the literal prefix, which is ten
	// characters carrying two underscores. Standard base64 writes no underscore
	// at all, so a certificate, a PEM body or an embedded image holds no
	// candidate at however long it runs; a base64url payload holds the
	// characters but has to put those ten in a row.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a base64url run behind the prefix",
			src:  "sb_secret_0123456789abcdef012345_01234567",
			want: []Span{{0, 41}},
		},
		{
			name: "a longer base64url run behind the prefix",
			src:  "sb_secret_0123456789abcdef012345_012345670123456789abcdef",
			want: []Span{{0, 41}},
		},
		{
			name: "a base64url run on its own",
			src:  "0123456789abcdef012345_01234567",
		},
		{
			name: "a standard base64 payload, which carries no underscore",
			src:  "payload=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsbsecret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := SupabaseSecretKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_supabaseSecretKeyPrefix(t *testing.T) {
	// The prefix is the argument the generator is called with for this kind of
	// key, and it is the whole of what tells one from a publishable key.
	if got := supabaseSecretKeyPrefix; got != "sb_secret_" {
		t.Errorf("supabaseSecretKeyPrefix = %q, want %q", got, "sb_secret_")
	}
}

func Test_supabaseSecretKeyAnchor(t *testing.T) {
	// The byte the scan searches for stands at the index it reads a candidate
	// back from. A prefix or an index changed without the other leaves the scan
	// opening candidates nowhere near where a key begins, and what such a scan
	// finds is nothing at all rather than something wrong.
	if got := supabaseSecretKeyPrefix[supabaseSecretKeyAnchorIndex]; got != supabaseSecretKeyAnchor {
		t.Errorf("supabaseSecretKeyPrefix[%d] = %q, want the anchor %q",
			supabaseSecretKeyAnchorIndex, got, supabaseSecretKeyAnchor)
	}

	// What the choice of byte rests on, counted rather than claimed in prose:
	// it stands once in this prefix, so a line of keys stops the search once a
	// key. A byte standing twice would cost a stop the rationale does not
	// account for.
	if n := strings.Count(supabaseSecretKeyPrefix, string(supabaseSecretKeyAnchor)); n != 1 {
		t.Errorf("the anchor stands %d times in %q, want 1", n, supabaseSecretKeyPrefix)
	}
}

func Test_supabaseSecretKeyChars(t *testing.T) {
	// The counts the generator slices and what they come to. Twenty-two
	// characters of randomness, the separator it writes behind them and the
	// eight the checksum is cut to make a body of thirty-one, and the prefix in
	// front of it makes a key of forty-one.
	if got := supabaseSecretKeyRandomChars; got != 22 {
		t.Errorf("supabaseSecretKeyRandomChars = %d, want 22", got)
	}
	if got := supabaseSecretKeyChecksumChars; got != 8 {
		t.Errorf("supabaseSecretKeyChecksumChars = %d, want 8", got)
	}
	if got := supabaseSecretKeyBodyChars; got != 31 {
		t.Errorf("supabaseSecretKeyBodyChars = %d, want 31", got)
	}
	if got := supabaseSecretKeyChars; got != 41 {
		t.Errorf("supabaseSecretKeyChars = %d, want 41", got)
	}
}

func Test_isSupabaseKeyBody(t *testing.T) {
	// The body both halves of this format share, read on its own. It is handed
	// the count as well as the characters, so a caller that cut the wrong
	// number of them is answered rather than trusted.
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "a body",
			s:    "0123456789abcdef012345_01234567",
			want: true,
		},
		{
			name: "a body of every character the alphabet has",
			s:    "ABCDEFGHIJKLMNOPQRSTUV_wxyz-_09",
			want: true,
		},
		{
			name: "one character short",
			s:    "0123456789abcdef012345_0123456",
		},
		{
			name: "one character long",
			s:    "0123456789abcdef012345_012345678",
		},
		{
			name: "no separator",
			s:    "0123456789abcdef01234501234567",
		},
		{
			name: "the separator a character early",
			s:    "0123456789abcdef01234_501234567",
		},
		{
			name: "a hyphen where the separator stands",
			s:    "0123456789abcdef012345-01234567",
		},
		{
			name: "a character outside the alphabet",
			s:    "0123456789abcdef01234._01234567",
		},
		{
			name: "empty",
			s:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSupabaseKeyBody(tt.s); got != tt.want {
				t.Errorf("isSupabaseKeyBody(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

// referenceSupabaseSecretKey is the grammar as a regular expression: the prefix
// the generator is called with, the twenty-two characters it slices out of a
// base64url encoding, the separator it writes behind them and the eight
// characters of checksum. Every part of it is spelled again rather than read
// from the scan, so that the two can disagree and the target below report it.
//
// It is built on an expression rather than written out because neither thing
// that has made one too slow to fuzz with is here. Both counts are exact, so an
// engine reads the machine once and stops rather than carrying a machine as wide
// as a floor through every candidate; and the opening is a ten character literal
// rather than a class, so an engine searches the text for it and skips rather
// than walking its machine at every byte — which matters here more than it would
// elsewhere, since the alphabet the body is drawn from holds every character
// that literal is written with.
var referenceSupabaseSecretKey = regexp.MustCompile(`sb_secret_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{8}`)

// referenceSupabaseSecretKeyFind locates keys the plain way: the leftmost match
// of the expression above, then the leftmost one beginning after that match's
// first byte, over and over, with nothing remembered between them.
//
// Asking at every byte rather than resuming past a match is what the scan does
// and is what a key written inside another needs: a body may spell the prefix,
// so a match can begin ten characters into the one before it and resuming past
// the first would lose it.
func referenceSupabaseSecretKeyFind(src string) []Span {
	var spans []Span
	for i := 0; i < len(src); {
		loc := referenceSupabaseSecretKey.FindStringIndex(src[i:])
		if loc == nil {
			break
		}
		start := i + loc[0]
		spans = append(spans, Span{Start: start, End: i + loc[1]})
		i = start + 1
	}
	return spans
}

// FuzzSupabaseSecretKey_matchesReference guards the hand-written scan: the
// prefix it searches for, the counts it reads behind that prefix, the character
// it demands between them, the alphabet it reads them in and the byte it
// resumes at may none of them change which keys are located.
func FuzzSupabaseSecretKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("SUPABASE_SECRET_KEY=sb_secret_0123456789abcdef012345_01234567")
	f.Add("sb_secret_0123456789abcdef012345_0123456")   // a body one character short
	f.Add("sb_secret_0123456789abcdef012345_012345678") // and a run one longer
	f.Add("sb_secret_0123456789abcdef01234_501234567")  // the separator a character early
	f.Add("sb_secret_0123456789abcdef0123450_1234567")  // and a character late
	f.Add("sb_secret_0123456789abcdef01234501234567")   // no separator at all
	f.Add("sb_secret_0123456789abcdef012345-01234567")  // a hyphen where it stands
	f.Add("sb_secret_0123456789_bcdef012345_01234567")  // an underscore elsewhere in the body
	f.Add("sb_secret_0123456789-bcdef012345_01234567")  // and a hyphen
	f.Add("sb_secret_0123456789ABCDEF012345_01234567")  // an uppercase body
	f.Add("sb_secret_0123456789.bcdef012345_01234567")  // a character outside the alphabet
	f.Add("sb_secret_0123456789abcdef012345_0123456.")  // and one at the end of the checksum
	f.Add("sb_secret_0123456789abcdef012345\n01234567")
	f.Add("sb_secret-0123456789abcdef012345_01234567") // a hyphen where the prefix closes
	f.Add("SB_SECRET_0123456789abcdef012345_01234567") // an uppercase prefix
	f.Add("xsb_secret_0123456789abcdef012345_01234567")
	// The other half of this format, which this pattern locates nothing in.
	f.Add("sb_publishable_0123456789abcdef012345_01234567")
	// A key written inside another, which a scan resuming past a match would
	// lose, and two keys with nothing between them.
	f.Add("sb_secret_sb_secret_0123456789ab_012345670_01234567")
	f.Add("sb_secret_sb_secret_0123456789abcdef012345_01234567")
	f.Add("sb_secret_0123456789abcdef012345_01234567sb_secret_0123456789abcdef012345_01234567")
	// Candidate positions crowded as close as they can be, and runs of the two
	// characters a candidate is opened and divided by.
	f.Add(strings.Repeat("sb_secret_", 32))
	f.Add(strings.Repeat("sb_secret_", 32) + "0123456789abcdef012345_01234567")
	f.Add(strings.Repeat("sb_secret_0123456789abcdef012345_01234567", 8))
	f.Add(strings.Repeat("_", 128))
	f.Add(strings.Repeat("b", 128))
	// The other Supabase credentials, which this pattern locates nothing in.
	f.Add("sbp_0123456789abcdef0123456789abcdef01234567")
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.0123456789abcdef")

	fuzzAgainstReference(f, SupabaseSecretKey().Find, referenceSupabaseSecretKeyFind)
}

// supabaseSecretKeyFindBenchmarks is what this scan is timed on. The
// builtinPatterns entry for the pattern names it, and BenchmarkBuiltins times
// every case it holds under the pattern's own name, so that a built-in cannot
// arrive without a benchmark. Every case is held to the count it states under a
// plain go test as well, which is what a benchmark nobody has run yet cannot be.
func supabaseSecretKeyFindBenchmarks() []benchmarkCase {
	// The line the anchor is chosen against: the b of the vendor's own name
	// stands once on it where the s stands six times, and the underscore the
	// prefix closes with stands not once. What the line times is the search for
	// the anchor, which is most of what this pattern costs a caller whose text
	// holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="calling api" url=https://api.supabase.co/rest/v1/todos `
	key := "sb_secret_0123456789abcdef012345_01234567"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// A candidate for every eleven characters, each carrying a whole
			// prefix, and each turned away by the character the separator would
			// have to stand at — which is the cheapest this scan declines a
			// candidate that got as far as its body.
			//
			// The character behind each prefix is what keeps them candidates: a
			// run of the prefix alone is a run of keys instead, since the body
			// it leaves puts the prefix's own underscore where the separator
			// belongs.
			name:  "candidates that are not values",
			src:   strings.Repeat("sb_secret_0", 512),
			spans: 0,
		},
		{
			// A run of the anchor byte alone: every position stops the search
			// and none of them reads a prefix, which is the cheapest a
			// candidate is declined for at all.
			name:  "anchors that open no candidate",
			src:   strings.Repeat("b", 4096),
			spans: 0,
		},
		{
			// The other way a candidate fails: a body of the right alphabet up
			// to its last character, so the whole of it is walked before the
			// candidate is turned away.
			name:  "candidates walked to their last character",
			src:   strings.Repeat("sb_secret_0123456789abcdef012345_0123456. ", 16),
			spans: 0,
		},
		{
			name:  "one value",
			src:   line + "apikey=" + key,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "apikey=" + key,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"apikey="+key+"\n", 32),
			spans: 32,
		},
	}
}
