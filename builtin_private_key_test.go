package mask

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// The private key pattern: what it locates and what it leaves alone, written
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
// shape, obviously not real. A real key runs to hundreds of characters over
// dozens of lines, and nothing this scan reads is sensitive to how many of
// either there are, so the blocks here carry a line or two.

func Test_PrivateKey(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a block on its own",
			src:  "-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----",
			want: []Span{{0, 70}},
		},
		{
			// The label OpenSSH writes, which its sshkey.c spells out as
			// MARK_BEGIN.
			name: "an openssh block",
			src:  "-----BEGIN OPENSSH PRIVATE KEY-----\n0123456789abcdef\n-----END OPENSSH PRIVATE KEY-----",
			want: []Span{{0, 86}},
		},
		{
			// The words RFC 9580 writes, which end on BLOCK where every other
			// label ends on KEY, together with the armor header and the CRC24
			// line that document puts around the data.
			name: "a pgp block with an armor header and a checksum",
			src:  "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n0123456789abcdef\n=0123\n-----END PGP PRIVATE KEY BLOCK-----",
			want: []Span{{0, 115}},
		},
		{
			// What RFC 1421 puts in front of the data of a key OpenSSL
			// encrypted, and the blank line that closes the headers.
			name: "a block with the headers of an encrypted key",
			src:  "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0123456789abcdef\n\n0123456789abcdef\n-----END RSA PRIVATE KEY-----",
			want: []Span{{0, 141}},
		},
		{
			// The line breaks written as the two characters \ and n, which is
			// how a service account key reaches a program through JSON.
			name: "a block in a json string",
			src:  `{"private_key":"-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----\n"}`,
			want: []Span{{16, 88}},
		},
		{
			// The solidus is a character of the base64 alphabet, and JSON may
			// escape it — PHP's json_encode does by default. A body line
			// carrying one unread is a line that is not base64 to its end,
			// which loses the whole key rather than the character.
			name: "a json string whose solidus is escaped",
			src:  `{"private_key":"-----BEGIN PRIVATE KEY-----\n0123456789abcdef\/0123456789abcdef\n-----END PRIVATE KEY-----\n"}`,
			want: []Span{{16, 106}},
		},
		{
			name: "a checksum whose solidus is escaped",
			src:  "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n0123456789abcdef\n=012\\/\n-----END PGP PRIVATE KEY BLOCK-----",
			want: []Span{{0, 98}},
		},
		{
			// A blank line ends the body, so a key one was pasted into the
			// middle of is located only as far as that line.
			// builtin_private_key.go says what that gives up and why the
			// alternative reaches further than the value.
			name: "a blank line inside the base64 ends the block",
			src:  "-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n\n0123456789abcdef\n-----END PRIVATE KEY-----",
			want: []Span{{0, 44}},
		},
		{
			name: "a block in an environment assignment with escaped line breaks",
			src:  `PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----`,
			want: []Span{{12, 84}},
		},
		{
			name: "a block written with carriage returns",
			src:  "-----BEGIN PRIVATE KEY-----\r\n0123456789abcdef\r\n-----END PRIVATE KEY-----",
			want: []Span{{0, 72}},
		},
		{
			// A label no document above defines. The words are the whole of
			// what is read, so a format written next is located without this
			// pattern being told about it.
			name: "a label no document defines",
			src:  "-----BEGIN QUANTUM PRIVATE KEY-----\n0123456789abcdef\n-----END QUANTUM PRIVATE KEY-----",
			want: []Span{{0, 86}},
		},
		{
			// The base64 of a key is whole bytes, so the last line of one
			// carries the padding that makes it up.
			name: "a body line carrying padding",
			src:  "-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n0123456789ab==\n-----END PRIVATE KEY-----",
			want: []Span{{0, 85}},
		},
		{
			// A log that stopped writing partway through a key. There is no
			// closing boundary to reach, so the block ends where its base64
			// does and the key is redacted as far as it was written.
			name: "a block cut short before its closing boundary",
			src:  "-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n0123456789ab",
			want: []Span{{0, 57}},
		},
		{
			// The far side of the same reading. Where the cut landed inside a
			// line — a key truncated in a quoted log message, so that the
			// quote and the rest of the record stand behind it — that line is
			// not base64 to its end and the block stops in front of it.
			// builtin_private_key.go says why reading the fragment as well was
			// declined.
			name: "a block cut short inside a line",
			src:  `msg="-----BEGIN PRIVATE KEY-----` + "\n0123456789abcdef\n0123456789ab" + `" level=info`,
			want: []Span{{5, 49}},
		},
		{
			// A closing boundary naming another label closes another block, so
			// this one ends at its base64 and that boundary stays in the text.
			name: "a closing boundary naming another label",
			src:  "-----BEGIN RSA PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----",
			want: []Span{{0, 48}},
		},
		{
			name: "what follows the closing boundary is left alone",
			src:  "-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----\ndone",
			want: []Span{{0, 70}},
		},
		{
			name: "two blocks one after the other",
			src:  "-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----",
			want: []Span{{0, 70}, {71, 141}},
		},
		{
			// A line that picked up a trailing space is one a hand-edited file
			// and a log are both full of. On the boundary line a scan that
			// would not read past it loses the whole key.
			name: "a boundary line closing on a tab",
			src:  "-----BEGIN PRIVATE KEY-----\t\n0123456789abcdef\n-----END PRIVATE KEY-----",
			want: []Span{{0, 71}},
		},
		{
			// On a body line it loses the rest of the key: the block would end
			// at the line above, which redacts most of a key and leaves what
			// is left reading as though the redaction had worked.
			name: "a body line closing on a space",
			src:  "-----BEGIN PRIVATE KEY-----\n0123456789abcdef \n0123456789abcdef\n-----END PRIVATE KEY-----",
			want: []Span{{0, 88}},
		},
		{
			// The spaces are not part of the value, so a block that ends at
			// its base64 ends where the base64 does.
			name: "a block cut short on a line closing with spaces",
			src:  "-----BEGIN PRIVATE KEY-----\n0123456789abcdef \n0123456789ab   ",
			want: []Span{{0, 58}},
		},
		{
			// The far side of the rule the case above states. The block whose
			// header carries a boundary is not one, and the block that
			// boundary opens is read on its own merits and located.
			name: "a boundary written inside a header value opens a block of its own",
			src:  "-----BEGIN PRIVATE KEY-----\nComment: -----BEGIN PRIVATE KEY-----\n\n0123456789abcdef\n-----END PRIVATE KEY-----",
			want: []Span{{37, 108}},
		},
		{
			// There is no floor under a body: the boundary line is the whole
			// of the evidence, so whatever stands where the key stands is
			// redacted. builtin_private_key.go says what a floor would cost.
			name: "a body of one character",
			src:  "-----BEGIN PRIVATE KEY-----\n0\n-----END PRIVATE KEY-----",
			want: []Span{{0, 55}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PrivateKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PrivateKey_indented(t *testing.T) {
	// A key written into YAML is indented under the name it is bound to, which
	// is how a Kubernetes secret, a Helm value and a docker-compose file each
	// carry one, and how a fenced block in a document does. Every line of a
	// block may therefore stand behind spaces or tabs.
	tests := []struct {
		name string
		src  string
		want []Span
	}{
		{
			name: "a block scalar under a name",
			src:  "privateKey: |\n  -----BEGIN PRIVATE KEY-----\n  0123456789abcdef\n  -----END PRIVATE KEY-----",
			want: []Span{{16, 90}},
		},
		{
			name: "a block indented with nothing above it",
			src:  "  -----BEGIN PRIVATE KEY-----\n  0123456789abcdef\n  -----END PRIVATE KEY-----",
			want: []Span{{2, 76}},
		},
		{
			// The headers, the blank line, the checksum and the closing
			// boundary stand behind an indent as the base64 does.
			name: "an indented block with headers and a checksum",
			src:  "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\tComment: 0123456789abcdef\n\n\t0123456789abcdef\n\t=0123\n\t-----END PGP PRIVATE KEY BLOCK-----",
			want: []Span{{0, 127}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PrivateKey().Find(tt.src); !slices.Equal(got, tt.want) {
				t.Errorf("Find(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PrivateKey_noMatch(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "a boundary with nothing behind it",
			src:  "-----BEGIN PRIVATE KEY-----",
		},
		{
			name: "a boundary closed by a line break and nothing else",
			src:  "-----BEGIN PRIVATE KEY-----\n",
		},
		{
			// The sentence a boundary is mentioned in. A line of prose carries
			// spaces, so it is not base64 to its end and the block has no
			// body — which is what keeps this pattern from reaching over the
			// documentation that explains it.
			name: "a boundary written into a sentence",
			src:  "the file starts with -----BEGIN RSA PRIVATE KEY----- and ends with -----END RSA PRIVATE KEY-----",
		},
		{
			// The same shape with the body separated by spaces rather than by
			// line breaks. Admitting the space is what would make the sentence
			// above a block.
			name: "a body separated by spaces",
			src:  "-----BEGIN PRIVATE KEY----- 0123456789abcdef -----END PRIVATE KEY-----",
		},
		{
			name: "a public key block",
			src:  "-----BEGIN PUBLIC KEY-----\n0123456789abcdef\n-----END PUBLIC KEY-----",
		},
		{
			name: "a certificate",
			src:  "-----BEGIN CERTIFICATE-----\n0123456789abcdef\n-----END CERTIFICATE-----",
		},
		{
			// RFC 9580 writes a public key block on the words PUBLIC KEY
			// BLOCK, which end on the same word a private one does and share
			// none of the two this reads.
			name: "a pgp public key block",
			src:  "-----BEGIN PGP PUBLIC KEY BLOCK-----\n0123456789abcdef\n-----END PGP PUBLIC KEY BLOCK-----",
		},
		{
			// The ssh.com format, whose boundary is four dashes with a space
			// inside them. It is a grammar of its own rather than a label this
			// pattern has not been told about.
			name: "four dashes with spaces inside them",
			src:  "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n0123456789abcdef\n---- END SSH2 ENCRYPTED PRIVATE KEY ----",
		},
		{
			name: "a lowercase label",
			src:  "-----BEGIN private key-----\n0123456789abcdef\n-----END private key-----",
		},
		{
			// The words must stand as words. A label running into them names
			// something else, and a label is read from a boundary rather than
			// from anything that vouches for it.
			name: "the words run into what comes in front of them",
			src:  "-----BEGIN NOTAPRIVATE KEY-----\n0123456789abcdef\n-----END NOTAPRIVATE KEY-----",
		},
		{
			name: "a label ending on neither of the words",
			src:  "-----BEGIN PRIVATE KEYS-----\n0123456789abcdef\n-----END PRIVATE KEYS-----",
		},
		{
			// RFC 7468 writes exactly one space between the word and the
			// label, and its ABNF puts a separator only between two label
			// characters.
			name: "two spaces inside the label",
			src:  "-----BEGIN RSA  PRIVATE KEY-----\n0123456789abcdef\n-----END RSA  PRIVATE KEY-----",
		},
		{
			name: "a boundary that does not close",
			src:  "-----BEGIN PRIVATE KEY\n0123456789abcdef\n-----END PRIVATE KEY",
		},
		{
			name: "four dashes in front of the word",
			src:  "----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----",
		},
		{
			name: "a body line broken by a space",
			src:  "-----BEGIN PRIVATE KEY-----\n0123456789 abcdef\n-----END PRIVATE KEY-----",
		},
		{
			// base64url rather than the standard alphabet. Every document
			// writing this envelope encodes with the standard one, where the
			// two characters base64url substitutes do not stand.
			name: "a body line written in base64url",
			src:  "-----BEGIN PRIVATE KEY-----\n0123456789abcdef-_\n-----END PRIVATE KEY-----",
		},
		{
			// Padding closes a line, so a character behind it is not base64
			// and the line is not one.
			name: "a body line carrying padding in the middle",
			src:  "-----BEGIN PRIVATE KEY-----\n0123==456789abcdef\n-----END PRIVATE KEY-----",
		},
		{
			// One blank line closes the headers, which is what both documents
			// write. Any number of them would let a block reach over a run of
			// empty lines to whatever word came next.
			name: "two blank lines in front of the body",
			src:  "-----BEGIN PRIVATE KEY-----\n\n\n0123456789abcdef\n-----END PRIVATE KEY-----",
		},
		{
			name: "an armor header and no body behind it",
			src:  "-----BEGIN PRIVATE KEY-----\nComment: 0123456789abcdef",
		},
		{
			// A log record and a YAML mapping are lines of the form word,
			// colon, text, and reading any such line as an armor header would
			// let a block written into one reach over every line behind it.
			// The six names the two documents define are what is read instead.
			name: "a line of the form word colon text is no armor header",
			src:  "key: -----BEGIN PRIVATE KEY-----\nerror: failed to load\npath: /etc/ssl/private/server.pem\n\n0123456789abcdef",
		},
		{
			name: "a header name neither document defines",
			src:  "-----BEGIN PRIVATE KEY-----\nX-Written-By: 0123456789abcdef\n\n0123456789abcdef\n-----END PRIVATE KEY-----",
		},
		{
			// A header value carrying a boundary would let one candidate read
			// over the candidate that boundary opens, which is what
			// Test_privateKey_scanIsLinear drives.
			name: "a header value carrying the dashes a boundary opens with",
			src:  "-----BEGIN PRIVATE KEY-----\nComment: ----- and nothing else\n\n0123456789abcdef",
		},
		{
			// A text is escaped or it is not. A real carriage return in front
			// of an escaped line feed is neither, and is no line break here.
			name: "a line break written half escaped",
			src:  "-----BEGIN PRIVATE KEY-----\r\\n0123456789abcdef",
		},
		{
			name: "a line break written half unescaped",
			src:  `-----BEGIN PRIVATE KEY-----\r` + "\n0123456789abcdef",
		},
		{
			// What reading the spaces gives up nothing of: a word behind the
			// space is not the end of a line, so the sentence a boundary is
			// mentioned in is still no block.
			name: "a boundary line closing on a space with a word behind it",
			src:  "-----BEGIN PRIVATE KEY----- and ends with -----END PRIVATE KEY-----",
		},
		{
			name: "an indented body line broken by a space",
			src:  "-----BEGIN PRIVATE KEY-----\n  0123456789 abcdef\n-----END PRIVATE KEY-----",
		},
		{
			// One level of escaping is read. A JSON string encoded into
			// another writes its line breaks with two backslashes, and a
			// block written that way is located nowhere.
			name: "a text escaped twice over",
			src:  `-----BEGIN PRIVATE KEY-----\\n0123456789abcdef\\n-----END PRIVATE KEY-----`,
		},
		{
			name: "prose",
			src:  "there is no credential in this sentence",
		},
		{
			name: "a git sha",
			src:  "0123456789abcdef0123456789abcdef01234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := PrivateKey().Find(tt.src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", tt.src, got)
			}
		})
	}
}

func Test_PrivateKey_inContext(t *testing.T) {
	// The whole block is redacted, the two boundary lines included, so the line
	// breaks inside it are written over as well and what was several lines
	// comes back as one run. Fixed is what a caller who wants the shape of the
	// text kept reaches for.
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a block on its own",
			src:  "-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----",
			want: "**********************************************************************",
		},
		{
			name: "a block between lines that are not part of it",
			src:  "writing the key\n-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----\nwritten",
			want: "writing the key\n**********************************************************************\nwritten",
		},
		{
			name: "a block in a json string",
			src:  `{"private_key":"-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----\n"}`,
			want: `{"private_key":"************************************************************************\n"}`,
		},
	}

	m := New(WithPatterns(PrivateKey()))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.Mask(tt.src); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func Test_PrivateKey_theLabelsTheDocumentsDefine(t *testing.T) {
	// Every label the documents behind this pattern write, held to being
	// located under one body. builtin_private_key.go reads the words a label
	// ends on rather than a roster of labels, so what this states is that the
	// reading reaches each of them — not that the roster is complete, which is
	// a claim about the world rather than about the scan.
	labels := []string{
		"PRIVATE KEY",           // RFC 7468 section 10
		"ENCRYPTED PRIVATE KEY", // RFC 7468 section 11
		"RSA PRIVATE KEY",       // PKCS#1, as OpenSSL writes it
		"DSA PRIVATE KEY",       // OpenSSL
		"EC PRIVATE KEY",        // RFC 5915
		"OPENSSH PRIVATE KEY",   // OpenSSH, sshkey.c
		"PGP PRIVATE KEY BLOCK", // RFC 9580
	}

	p := PrivateKey()
	for _, label := range labels {
		t.Run(label, func(t *testing.T) {
			src := "-----BEGIN " + label + "-----\n0123456789abcdef\n-----END " + label + "-----"
			want := []Span{{0, len(src)}}
			if got, _ := p.Find(src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", src, got, want)
			}
		})
	}
}

func Test_PrivateKey_labelsTheEnvelopeCarriesThatAreNotKeys(t *testing.T) {
	// The other side of the same reading: the labels RFC 7468 defines for
	// everything that is not a private key, none of which may be located. This
	// is what the words are for — the envelope is shared, and the label is the
	// only thing in it that says which of the two a block is.
	labels := []string{
		"CERTIFICATE",
		"X509 CRL",
		"CERTIFICATE REQUEST",
		"PKCS7",
		"CMS",
		"ATTRIBUTE CERTIFICATE",
		"PUBLIC KEY",
		"PGP PUBLIC KEY BLOCK",
		"PGP MESSAGE",
		"PGP SIGNATURE",
	}

	p := PrivateKey()
	for _, label := range labels {
		t.Run(label, func(t *testing.T) {
			src := "-----BEGIN " + label + "-----\n0123456789abcdef\n-----END " + label + "-----"
			if got, _ := p.Find(src); len(got) != 0 {
				t.Errorf("Find(%q) = %v, want no span", src, got)
			}
		})
	}
}

func Test_PrivateKey_everyLineBreakSpelling(t *testing.T) {
	// The four spellings a line break is read in, each written through a whole
	// block. The escaped two are what a key carried through JSON or through an
	// environment assignment is written with, and a scan reading only the real
	// ones would leave the commonest written form of a private key whole.
	breaks := map[string]string{
		"a line feed":                              "\n",
		"a carriage return and a line feed":        "\r\n",
		"an escaped line feed":                     `\n`,
		"an escaped carriage return and line feed": `\r\n`,
	}

	// Every spelling, which is what the name claims and what the cases above
	// cannot say on their own: a fifth added to privateKeyLineBreaks would
	// leave them passing and the name false.
	if got, want := len(breaks), len(privateKeyLineBreaks); got != want {
		t.Fatalf("%d spelling(s) are written out here and the scan reads %d", got, want)
	}

	p := PrivateKey()
	for name, br := range breaks {
		t.Run(name, func(t *testing.T) {
			src := "-----BEGIN PRIVATE KEY-----" + br + "0123456789abcdef" + br + "-----END PRIVATE KEY-----"
			want := []Span{{0, len(src)}}
			if got, _ := p.Find(src); !slices.Equal(got, want) {
				t.Errorf("Find(%q) = %v, want %v", src, got, want)
			}
		})
	}
}

func Test_privateKeyAnchor(t *testing.T) {
	// The prefix must carry the byte the scan searches the input for at the
	// index it reads a candidate back from. builtin_scan.go says why that is
	// held here rather than left to the fuzz target: a prefix and an index that
	// have come apart locate nothing, and a scan finding nothing is what a
	// target beside a reference doing the same reports as agreement.
	if privateKeyAnchorIndex >= len(privateKeyPrefix) {
		t.Fatalf("the anchor stands at %d, the prefix is %d characters", privateKeyAnchorIndex, len(privateKeyPrefix))
	}
	if c := privateKeyPrefix[privateKeyAnchorIndex]; c != privateKeyAnchor {
		t.Errorf("the prefix carries %q where the scan searches for %q, so no candidate is ever found at it", c, byte(privateKeyAnchor))
	}
}

func Test_privateKeyBoundaries(t *testing.T) {
	// What the two boundaries and the run of dashes have to hold of one
	// another. Each opening and closing prefix opens with the dashes and closes
	// with the space RFC 7468 writes, and the dash belongs to neither the label
	// alphabet nor the base64 one — which is the whole of what keeps two
	// candidates from reading the same run, and so the whole of what makes the
	// scan linear.
	for _, prefix := range []string{privateKeyPrefix, privateKeyEndPrefix} {
		if !strings.HasPrefix(prefix, privateKeyBoundary) {
			t.Errorf("%q does not open with %q", prefix, privateKeyBoundary)
		}
		if !strings.HasSuffix(prefix, " ") {
			t.Errorf("%q does not close with the space a label stands behind", prefix)
		}
	}
	for i := range len(privateKeyBoundary) {
		c := privateKeyBoundary[i]
		if isPrivateKeyLabelByte(c) {
			t.Errorf("the boundary holds %q, which a label may be written with, so a label run can reach over one", c)
		}
		if isPrivateKeyBase64Byte(c) {
			t.Errorf("the boundary holds %q, which base64 may be written with, so a body can reach over one", c)
		}
	}
}

func Test_privateKeyHeaderNames(t *testing.T) {
	// The roster of armor headers, and what it has to hold of itself. Each name
	// must be read as one where a colon follows it and nowhere else, and no
	// name may be a prefix of another — privateKeyHeaderNameAt returns the
	// first that matches, so a name reachable only behind another would be
	// read as that one and its own colon never asked for.
	if len(privateKeyHeaderNames) == 0 {
		t.Fatal("no armor header is read, so no encrypted key carries its headers into a block")
	}
	for i, name := range privateKeyHeaderNames {
		t.Run(name, func(t *testing.T) {
			if got := privateKeyHeaderNameAt(name+":", 0); got != len(name) {
				t.Errorf("privateKeyHeaderNameAt(%q) = %d, want %d", name+":", got, len(name))
			}
			if got := privateKeyHeaderNameAt(name, 0); got != 0 {
				t.Errorf("privateKeyHeaderNameAt(%q) = %d, want 0; a name with no colon behind it is no header", name, got)
			}
			for j, other := range privateKeyHeaderNames {
				if i != j && strings.HasPrefix(other, name) {
					t.Errorf("%q opens %q, so the shorter is read first and the longer never asked for", name, other)
				}
			}
		})
	}
}

func Test_privateKeyHeaderLineEnd_stopsAtABoundary(t *testing.T) {
	// The rule the linearity of this scan rests on: a header value may carry
	// anything but the dashes a boundary opens with. Stated over the roster
	// rather than over one name, since it is the value that is read and every
	// name reaches the same reading.
	for _, name := range privateKeyHeaderNames {
		t.Run(name, func(t *testing.T) {
			line := name + ": 0123456789abcdef"
			if got := privateKeyHeaderLineEnd(line, 0); got != len(line) {
				t.Errorf("privateKeyHeaderLineEnd(%q) = %d, want %d", line, got, len(line))
			}
			held := line + privateKeyBoundary + "BEGIN"
			if got := privateKeyHeaderLineEnd(held, 0); got != 0 {
				t.Errorf("privateKeyHeaderLineEnd(%q) = %d, want 0; a header carrying a boundary reads over the candidate it opens", held, got)
			}
			short := line + privateKeyBoundary[:len(privateKeyBoundary)-1]
			if got := privateKeyHeaderLineEnd(short, 0); got != len(short) {
				t.Errorf("privateKeyHeaderLineEnd(%q) = %d, want %d; one dash short of a boundary is no boundary", short, got, len(short))
			}
		})
	}
}

func Test_privateKeyLineBreaks(t *testing.T) {
	// The four spellings, and the two a carriage return and a line feed read
	// apart would add. A text is escaped or it is not, so a real carriage
	// return in front of an escaped line feed is neither and is no line break.
	for _, br := range privateKeyLineBreaks {
		if got := privateKeyLineBreak(br+"a", 0); got != len(br) {
			t.Errorf("privateKeyLineBreak(%q) = %d, want %d", br+"a", got, len(br))
		}
	}
	for _, mixed := range []string{"\r" + `\n`, `\r` + "\n"} {
		if got := privateKeyLineBreak(mixed+"a", 0); got != 0 {
			t.Errorf("privateKeyLineBreak(%q) = %d, want 0; the half escaped spellings are not read", mixed+"a", got)
		}
	}
}

func Test_privateKeySpaceEnd(t *testing.T) {
	// What a line may stand behind and what it may close on, over every byte:
	// spaces and tabs, and nothing else. A character the base64 or the label
	// alphabet holds would make this run one a candidate could read into
	// another's, which the linearity above rests on it not being.
	for c := range 256 {
		b := byte(c)
		src := string([]byte{b}) + "a"
		want := 0
		if b == ' ' || b == '\t' {
			want = 1
		}
		if got := privateKeySpaceEnd(src, 0); got != want {
			t.Errorf("privateKeySpaceEnd(%q) = %d, want %d", src, got, want)
		}
	}
}

func Test_privateKeyLabelSuffixes(t *testing.T) {
	// The words a label is held to end on, and what the narrowed label alphabet
	// has to keep reachable. A suffix carrying a character the alphabet does
	// not admit could stand at the end of no label, so the pattern would locate
	// nothing at all and every case above would fail together without saying
	// why.
	if len(privateKeyLabelSuffixes) == 0 {
		t.Fatal("no words are read, so the pattern locates nothing")
	}
	for _, suffix := range privateKeyLabelSuffixes {
		t.Run(suffix, func(t *testing.T) {
			if got, _ := privateKeyLabelEnd(suffix, 0); got != len(suffix) {
				t.Errorf("privateKeyLabelEnd(%q) = %d, want %d; the words are not a label the scan can read", suffix, got, len(suffix))
			}
			if !privateKeyLabelNamesAKey(suffix) {
				t.Errorf("privateKeyLabelNamesAKey(%q) = false, want a label that is nothing but the words to name a key", suffix)
			}
			if !privateKeyLabelNamesAKey("RSA " + suffix) {
				t.Errorf("privateKeyLabelNamesAKey(%q) = false, want the words behind another to name a key", "RSA "+suffix)
			}
			if privateKeyLabelNamesAKey("RSA" + suffix) {
				t.Errorf("privateKeyLabelNamesAKey(%q) = true, want the words to stand as words", "RSA"+suffix)
			}
		})
	}
}

func Test_isPrivateKeyLabelByte(t *testing.T) {
	// The alphabet a label is read in, stated over every byte rather than by
	// example: uppercase letters and digits, and nothing else. The space is not
	// one of them — privateKeyLabelEnd admits it between two of these and
	// nowhere else, which is what keeps a label from opening or closing with
	// one.
	for c := range 256 {
		b := byte(c)
		want := 'A' <= b && b <= 'Z' || '0' <= b && b <= '9'
		if got := isPrivateKeyLabelByte(b); got != want {
			t.Errorf("isPrivateKeyLabelByte(%q) = %v, want %v", b, got, want)
		}
	}
}

func Test_isPrivateKeyBase64Byte(t *testing.T) {
	// The alphabet a body is read in, stated over every byte: the standard
	// base64 of RFC 4648, which is what every document writing this envelope
	// encodes with. The padding is not part of it —
	// privateKeyBase64LineEnd reads at most two of those behind a run, and a
	// line opening with one is not a body line.
	for c := range 256 {
		b := byte(c)
		want := '0' <= b && b <= '9' || 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || b == '+' || b == '/'
		if got := isPrivateKeyBase64Byte(b); got != want {
			t.Errorf("isPrivateKeyBase64Byte(%q) = %v, want %v", b, got, want)
		}
	}
}

func Test_privateKey_scanIsLinear(t *testing.T) {
	// The claim builtin_private_key.go rests its linearity on: no candidate
	// reads a run another candidate already read, because the dash a boundary
	// opens with belongs to neither alphabet. Test_builtins_scanIsLinear drives
	// the samples repeated, which is a value crowded against itself; what is
	// crafted here is the input that would find the claim wrong — candidates
	// that are not values, sharing the runs a candidate walks.
	//
	// Two mebibytes for the reason that test gives, and scanIsLinearLimit for
	// how long that may take: what is crafted here costs a scan a fraction of
	// what the dearest of the samples repeated costs.
	const size = 2 << 20

	units := map[string]string{
		// Boundaries crowded against one another, each opening a candidate
		// that the byte behind it turns away.
		"boundaries with nothing behind them": "-----BEGIN PRIVATE KEY-----",
		// The same, each closed by a line break so that the candidate reads on
		// into a body it does not find.
		"boundaries closed by a line break": "-----BEGIN PRIVATE KEY-----\n",
		// A boundary whose label is one long run holding the anchor over and
		// over, so that every byte of the run opens a candidate and the one
		// candidate that reaches its label walks the whole run. A scan reading
		// the run again at each of them would be quadratic here.
		"a label run holding the anchor over and over": "-----BEGIN " + strings.Repeat("G", 64) + " PRIVATE KEY-----\n",
		// The anchor at every byte with no boundary anywhere, which is what
		// the search itself costs and reaches no candidate at all.
		"the anchor at every byte": "GGGGGGGG",
		// A body with no closing boundary, followed by the boundary that ends
		// it. A candidate reading past the run another candidate already read
		// is what this finds.
		"a body no boundary closes": "-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n",
		// Armor headers, which a candidate walks in front of a body it never
		// reaches.
		"armor headers with no body behind them": "-----BEGIN PRIVATE KEY-----\nComment: 0123456789abcdef\n",
		// A boundary written inside a header value. Every such line is a
		// header to the candidate in the line above it, so a header value free
		// to carry a boundary makes each candidate read to the end of the
		// input. This is the input privateKeyHeaderLineEnd stopping at a
		// boundary exists for.
		"a boundary inside a header value": "Comment: -----BEGIN PRIVATE KEY-----\n",
		// The same shape under a name the roster does not hold, which is what
		// a log record and a YAML mapping are. The roster turns this away at
		// the name, in front of the value.
		"a boundary inside a line that is no header": "priv: -----BEGIN PRIVATE KEY-----\n",
		// A boundary written directly against such a name, so that nothing
		// separates the candidate from the line that holds it.
		"a boundary against a name with no space": "x:-----BEGIN PRIVATE KEY-----\n",
	}

	m := New(WithPatterns(PrivateKey()))
	for name, unit := range units {
		t.Run(name, func(t *testing.T) {
			src := strings.Repeat(unit, size/len(unit)+1)
			start := time.Now()
			_ = m.Mask(src)
			if d := time.Since(start); d > scanIsLinearLimit {
				t.Errorf("Mask() of %d bytes of %q took %v", len(src), unit, d)
			}
		})
	}
}

// referencePrivateKeyFind locates blocks the plain way: at every byte of the
// input, ask whether a block begins there, with nothing remembered between one
// question and the next.
//
// It is written out rather than built on a regular expression, and not by
// preference. The closing boundary has to name the label the opening one named,
// which is a back reference, and RE2 has none — so no expression can state this
// grammar at all, and one stating the rest of it would leave the part most
// worth checking to hand-written code anyway. The four spellings a line break
// is read in are the second reason: written as an expression they stand inside
// every line rule at once, where here they are one function the rules call.
//
// The boundaries, the words, the alphabets and the spellings are spelled out
// again rather than read from builtin_private_key.go, so that the two can
// disagree and the fuzz target below report it.
//
// The shape is the one thing deliberately unlike the scan's. The scan walks
// forward by offset, reading a run and then asking what closed it; this cuts
// the text into lines first and then asks what each line is. Two readings of
// one grammar that agree on every input are worth more than two spellings of
// one reading.
//
// Asking at every byte is what the scan does as well, and is kept even though
// no block can begin inside another: a reference is written to know nothing its
// scan claims, and that no body carries a dash is a thing the scan claims.
func referencePrivateKeyFind(src string) []Span {
	var spans []Span
	for i := range len(src) {
		if end, ok := referencePrivateKeyBlockAt(src, i); ok {
			spans = append(spans, Span{Start: i, End: end})
		}
	}
	return spans
}

// referencePrivateKeyBlockAt reports where the block beginning at i in src
// ends, and whether one begins there at all.
func referencePrivateKeyBlockAt(src string, i int) (int, bool) {
	if !strings.HasPrefix(src[i:], "-----BEGIN ") {
		return 0, false
	}
	at := i + len("-----BEGIN ")

	end := referencePrivateKeyLabelEnd(src, at)
	label := src[at:end]
	if !referencePrivateKeyWords(label) {
		return 0, false
	}
	if !strings.HasPrefix(src[end:], "-----") {
		return 0, false
	}
	return referencePrivateKeyBody(src, end+len("-----"), label)
}

// referencePrivateKeyLabelEnd returns where the label beginning at i in src
// ends: uppercase letters and digits, with single spaces standing between two
// of them.
func referencePrivateKeyLabelEnd(src string, i int) int {
	isLabel := func(c byte) bool { return 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' }

	end := i
	for end < len(src) {
		switch {
		case isLabel(src[end]):
			end++
		case src[end] == ' ' && end > i && end+1 < len(src) && isLabel(src[end+1]):
			end += 2
		default:
			return end
		}
	}
	return end
}

// referencePrivateKeyWords reports whether label ends on the words a private
// key's label ends on, standing as words rather than run into what comes in
// front of them.
func referencePrivateKeyWords(label string) bool {
	for _, words := range []string{"PRIVATE KEY", "PRIVATE KEY BLOCK"} {
		if label == words {
			return true
		}
		if strings.HasSuffix(label, " "+words) {
			return true
		}
	}
	return false
}

// referencePrivateKeyBody reports where the block whose opening boundary ended
// at i in src ends, and whether anything stands behind that boundary at all.
//
// The lines are taken one at a time rather than all at once. A block is bounded
// by the first line that is none of the things below, and this is asked at
// every byte of the input, so reading every line of a block that ended pages
// ago is how a reference comes to take longer to run than the scan it checks.
func referencePrivateKeyBody(src string, i int, label string) (int, bool) {
	line, ok := referencePrivateKeyLine(src, i)
	if referencePrivateKeySpaced(line.text) != len(line.text) || !ok {
		return 0, false // the boundary line is closed by something else
	}
	i = line.next

	// Every line below is read past whatever it is indented by, which is what
	// reaches a key written into YAML.
	indent, held := 0, ""
	for {
		line, ok = referencePrivateKeyLine(src, i)
		held = referencePrivateKeyHeld(line.text)
		indent = referencePrivateKeyIndent(held)
		if !referencePrivateKeyHeader(held[indent:]) {
			break
		}
		if !ok {
			return 0, false // a header is the last line, so no body stands behind it
		}
		i = line.next
	}
	if held[indent:] == "" && ok {
		i = line.next // the blank line closing the headers
	}

	end, found := 0, false
	for {
		line, ok = referencePrivateKeyLine(src, i)
		held = referencePrivateKeyHeld(line.text)
		indent = referencePrivateKeyIndent(held)
		if !referencePrivateKeyBase64(held[indent:]) {
			break
		}
		end, found = line.end-(len(line.text)-len(held)), true
		if !ok {
			return end, true // the base64 reaches the end of the input
		}
		i = line.next
	}
	if !found {
		return 0, false
	}

	if referencePrivateKeyCRC(held[indent:]) {
		end = line.end - (len(line.text) - len(held))
		if !ok {
			return end, true
		}
		i = line.next
		line, _ = referencePrivateKeyLine(src, i)
		held = referencePrivateKeyHeld(line.text)
		indent = referencePrivateKeyIndent(held)
	}

	closing := "-----END " + label + "-----"
	if strings.HasPrefix(held[indent:], closing) {
		return i + indent + len(closing), true
	}
	return end, true
}

// referencePrivateKeyRun returns how much of text is a run of base64 — the
// solidus in it written plainly or as the two characters \ and / — with the
// padding a key's last line carries, and zero where text opens with none of
// those.
func referencePrivateKeyRun(text string) int {
	run := 0
	for run < len(text) {
		if referencePrivateKeyBase64Byte(text[run]) {
			run++
			continue
		}
		if !strings.HasPrefix(text[run:], `\/`) {
			break
		}
		run += 2
	}
	if run == 0 {
		return 0
	}
	for pad := 0; pad < 2 && run < len(text) && text[run] == '='; pad++ {
		run++
	}
	return run
}

// referencePrivateKeyBase64Byte reports whether c belongs to the standard
// base64 alphabet of RFC 4648.
func referencePrivateKeyBase64Byte(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || c == '+' || c == '/'
}

// referencePrivateKeyLineText is one line of the input: its text without the
// break that ended it, where that text ends, and where the next line begins.
type referencePrivateKeyLineText struct {
	text string
	end  int
	next int
}

// referencePrivateKeyLine returns the line beginning at i in src, and whether a
// line break ended it rather than the end of the input.
func referencePrivateKeyLine(src string, i int) (referencePrivateKeyLineText, bool) {
	for end := i; end < len(src); end++ {
		if w := referencePrivateKeyBreak(src, end); w > 0 {
			return referencePrivateKeyLineText{text: src[i:end], end: end, next: end + w}, true
		}
	}
	return referencePrivateKeyLineText{text: src[i:], end: len(src), next: len(src)}, false
}

// referencePrivateKeyBreak returns the width of the line break at i in src, in
// any of the four spellings, and zero where none stands there. Longest first,
// so that a carriage return is not left behind by the line feed after it.
func referencePrivateKeyBreak(src string, i int) int {
	for _, br := range []string{"\r\n", `\r\n`, "\n", `\n`} {
		if strings.HasPrefix(src[i:], br) {
			return len(br)
		}
	}
	return 0
}

// referencePrivateKeyHeader reports whether text is an armor header line: one
// of the six names the two documents define, a colon, and whatever follows
// short of the dashes a boundary opens with.
func referencePrivateKeyHeader(text string) bool {
	for _, name := range []string{"Proc-Type", "DEK-Info", "Version", "Comment", "Hash", "Charset"} {
		if strings.HasPrefix(text, name+":") {
			return !strings.Contains(text, "-----")
		}
	}
	return false
}

// referencePrivateKeyIndent returns how much of text is the spaces and tabs a
// line may be indented by.
func referencePrivateKeyIndent(text string) int {
	return referencePrivateKeySpaced(text)
}

// referencePrivateKeySpaced returns how much of text is spaces and tabs.
func referencePrivateKeySpaced(text string) int {
	n := 0
	for n < len(text) && (text[n] == ' ' || text[n] == '\t') {
		n++
	}
	return n
}

// referencePrivateKeyHeld returns text without the spaces and tabs that close
// it, which a line may pick up and which no reading below counts as content.
func referencePrivateKeyHeld(text string) string {
	return strings.TrimRight(text, " \t")
}

// referencePrivateKeyBase64 reports whether text is a base64 line: a run of the
// standard alphabet with its padding, reaching the end of the line and leaving
// nothing behind it.
func referencePrivateKeyBase64(text string) bool {
	run := referencePrivateKeyRun(text)
	return run > 0 && run == len(text)
}

// referencePrivateKeyCRC reports whether text is the checksum line RFC 9580
// writes behind an armored block: an = and the four characters three bytes of
// base64 come to.
func referencePrivateKeyCRC(text string) bool {
	if !strings.HasPrefix(text, "=") {
		return false
	}
	at := len("=")
	for range 4 {
		switch {
		case at < len(text) && referencePrivateKeyBase64Byte(text[at]):
			at++
		case strings.HasPrefix(text[at:], `\/`):
			at += 2
		default:
			return false
		}
	}
	return at == len(text)
}

// FuzzPrivateKey_matchesReference guards the hand-written scan: the boundaries
// it reads, the words it holds a label to, the alphabets it reads a label and a
// body in, the spellings it reads a line break in and the byte it resumes at
// may none of them change which blocks are located.
func FuzzPrivateKey_matchesReference(f *testing.F) {
	f.Add("nothing to see here")
	f.Add("-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----")
	f.Add("-----BEGIN OPENSSH PRIVATE KEY-----\n0123456789abcdef\n-----END OPENSSH PRIVATE KEY-----")
	f.Add("-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n0123456789abcdef\n=0123\n-----END PGP PRIVATE KEY BLOCK-----")
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0123456789abcdef\n\n0123456789abcdef\n-----END RSA PRIVATE KEY-----")
	f.Add(`{"private_key":"-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----\n"}`)
	f.Add("-----BEGIN PRIVATE KEY-----\r\n0123456789abcdef\r\n-----END PRIVATE KEY-----")
	f.Add(`-----BEGIN PRIVATE KEY-----\r\n0123456789abcdef\r\n-----END PRIVATE KEY-----`)
	// A block cut short, a boundary with nothing behind it, and a boundary
	// closed by something other than a line break.
	f.Add("-----BEGIN PRIVATE KEY-----\n0123456789ab")
	f.Add("-----BEGIN PRIVATE KEY-----")
	f.Add("-----BEGIN PRIVATE KEY-----\n")
	f.Add("-----BEGIN PRIVATE KEY----- 0123456789abcdef -----END PRIVATE KEY-----")
	// The labels the envelope carries that are not keys, and the words run
	// into what comes in front of them.
	f.Add("-----BEGIN CERTIFICATE-----\n0123456789abcdef\n-----END CERTIFICATE-----")
	f.Add("-----BEGIN PUBLIC KEY-----\n0123456789abcdef\n-----END PUBLIC KEY-----")
	f.Add("-----BEGIN NOTAPRIVATE KEY-----\n0123456789abcdef\n-----END NOTAPRIVATE KEY-----")
	f.Add("-----BEGIN RSA  PRIVATE KEY-----\n0123456789abcdef\n-----END RSA  PRIVATE KEY-----")
	// A closing boundary naming another label, and one naming a longer label
	// that opens with this one's.
	f.Add("-----BEGIN RSA PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY-----")
	f.Add("-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n-----END PRIVATE KEY BLOCK-----")
	// Candidate positions crowded as close as they can be.
	f.Add(strings.Repeat("-----BEGIN PRIVATE KEY-----", 8))
	f.Add(strings.Repeat("-----BEGIN PRIVATE KEY-----\n", 8))
	f.Add(strings.Repeat("-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n", 8))
	f.Add(strings.Repeat("-----BEGIN G PRIVATE KEY-----", 8))
	f.Add("-----BEGIN " + strings.Repeat("G", 32) + " PRIVATE KEY-----\n0123456789abcdef")
	// Padding, a checksum where no checksum belongs, and blank lines.
	f.Add("-----BEGIN PRIVATE KEY-----\n0123456789ab==\n-----END PRIVATE KEY-----")
	f.Add("-----BEGIN PRIVATE KEY-----\n=0123\n-----END PRIVATE KEY-----")
	f.Add("-----BEGIN PRIVATE KEY-----\n\n0123456789abcdef\n-----END PRIVATE KEY-----")
	f.Add("-----BEGIN PRIVATE KEY-----\n\n\n0123456789abcdef\n-----END PRIVATE KEY-----")
	f.Add("-----BEGIN PRIVATE KEY-----\nComment: 0123456789abcdef")
	f.Add("-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n=0123")
	// Indented blocks, and the indents that are not.
	f.Add("privateKey: |\n  -----BEGIN PRIVATE KEY-----\n  0123456789abcdef\n  -----END PRIVATE KEY-----")
	f.Add("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\tComment: 0123456789abcdef\n\n\t0123456789abcdef\n\t=0123\n\t-----END PGP PRIVATE KEY BLOCK-----")
	f.Add("-----BEGIN PRIVATE KEY-----\n  0123456789 abcdef\n-----END PRIVATE KEY-----")
	f.Add("-----BEGIN PRIVATE KEY-----\n   \n  0123456789abcdef")
	// The armor headers, the names that are none, and a value carrying a
	// boundary.
	f.Add("-----BEGIN PRIVATE KEY-----\nX-Written-By: 0123456789abcdef\n\n0123456789abcdef\n-----END PRIVATE KEY-----")
	f.Add("key: -----BEGIN PRIVATE KEY-----\nerror: failed to load\npath: /etc/ssl/private/server.pem\n\n0123456789abcdef")
	f.Add("-----BEGIN PRIVATE KEY-----\nComment: ----- and nothing else\n\n0123456789abcdef")
	f.Add("-----BEGIN PRIVATE KEY-----\nComment: -----BEGIN PRIVATE KEY-----\n\n0123456789abcdef\n-----END PRIVATE KEY-----")
	f.Add(strings.Repeat("Comment: -----BEGIN PRIVATE KEY-----\n", 8))
	f.Add(strings.Repeat("priv: -----BEGIN PRIVATE KEY-----\n", 8))
	f.Add("-----BEGIN PRIVATE KEY-----\nComment:\n\n0123456789abcdef")
	// The line breaks written half escaped, which are no line breaks.
	f.Add("-----BEGIN PRIVATE KEY-----\r\\n0123456789abcdef")
	f.Add(`-----BEGIN PRIVATE KEY-----\r` + "\n0123456789abcdef")
	// A backslash that is not a line break, and one at the very end.
	f.Add(`-----BEGIN PRIVATE KEY-----\x0123456789abcdef`)
	f.Add(`-----BEGIN PRIVATE KEY-----\`)
	// Lines closing on spaces and tabs, at both ends of a block and inside it.
	f.Add("-----BEGIN PRIVATE KEY-----\t\n0123456789abcdef\n-----END PRIVATE KEY-----")
	f.Add("-----BEGIN PRIVATE KEY-----\n0123456789abcdef \n0123456789abcdef\n-----END PRIVATE KEY-----")
	f.Add("-----BEGIN PRIVATE KEY-----\n0123456789abcdef \n0123456789ab   ")
	f.Add("-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n  \n-----END PRIVATE KEY-----")
	f.Add("-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n=0123 \n  -----END PRIVATE KEY-----  ")
	f.Add("-----BEGIN PRIVATE KEY----- ")
	// The solidus written escaped, in a body and in a checksum, and a text
	// escaped twice over.
	f.Add(`{"private_key":"-----BEGIN PRIVATE KEY-----\n0123456789abcdef\/0123456789abcdef\n-----END PRIVATE KEY-----\n"}`)
	f.Add("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n0123456789abcdef\n=012\\/\n-----END PGP PRIVATE KEY BLOCK-----")
	f.Add(`-----BEGIN PRIVATE KEY-----\n0123456789abcdef\/\n-----END PRIVATE KEY-----`)
	f.Add(`-----BEGIN PRIVATE KEY-----\\n0123456789abcdef\\n-----END PRIVATE KEY-----`)
	f.Add(`-----BEGIN PRIVATE KEY-----` + "\n0123456789abcdef" + `\` + "\n-----END PRIVATE KEY-----")
	f.Add("-----BEGIN PRIVATE KEY-----\n0123456789abcdef\n\n0123456789abcdef\n-----END PRIVATE KEY-----")

	fuzzAgainstReference(f, PrivateKey().Find, referencePrivateKeyFind)
}

// privateKeyFindBenchmarks is what this scan is timed on. The builtinPatterns
// entry for the pattern names it, and BenchmarkBuiltins times every case it
// holds under the pattern's own name, so that a built-in cannot arrive without
// a benchmark. Every case is held to the count it states under a plain go test
// as well, which is what a benchmark nobody has run yet cannot be.
func privateKeyFindBenchmarks() []benchmarkCase {
	// Nothing in an ordinary line carries the anchor, so what the line times is
	// the search for it — which is most of what this pattern costs a caller
	// whose text holds no key.
	line := `time=2026-08-17T00:00:00Z level=info msg="loading the signing key" path=/etc/ssl/private/server.pem `
	block := "-----BEGIN PRIVATE KEY-----\n" +
		strings.Repeat("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n", 24) +
		"-----END PRIVATE KEY-----"

	return []benchmarkCase{
		{
			name:  "no value",
			src:   line,
			spans: 0,
		},
		{
			// Boundaries crowded against one another, each opening a candidate
			// the byte behind it turns away. This is what a candidate that is
			// not a value costs, with no value at the end of any of it.
			name:  "candidates that are not values",
			src:   strings.Repeat("-----BEGIN PRIVATE KEY-----", 64),
			spans: 0,
		},
		{
			// The run this scan walks at length: a body of the size a real key
			// runs to, read line by line to the boundary that closes it.
			name:  "one value",
			src:   line + "\n" + block,
			spans: 1,
		},
		{
			name:  "one value in a long line",
			src:   strings.Repeat(line, 32) + "\n" + block,
			spans: 1,
		},
		{
			name:  "many values",
			src:   strings.Repeat(line+"\n"+block+"\n", 8),
			spans: 8,
		},
	}
}
