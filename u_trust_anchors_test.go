package tls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"testing"
)

// TestTrustAnchorsCodepoint pins the codepoint that BoringSSL uses, since the draft
// has not been assigned one by IANA yet.
func TestTrustAnchorsCodepoint(t *testing.T) {
	if utlsExtensionTrustAnchors != 0xca34 {
		t.Errorf("trust_anchors codepoint = 0x%04x, want 0xca34", utlsExtensionTrustAnchors)
	}
}

// TestTrustAnchorsEmptyWireFormat checks the bytes Chrome puts on the wire when it has
// no trust anchor hint from DNS, which is the common case: the extension is present but
// its list is empty.
func TestTrustAnchorsEmptyWireFormat(t *testing.T) {
	ext := &TrustAnchorsExtension{}

	if got, want := ext.Len(), 6; got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}

	b := make([]byte, ext.Len())
	n, err := ext.Read(b)
	if err != io.EOF {
		t.Fatalf("Read: %v, want io.EOF", err)
	}
	if n != len(b) {
		t.Fatalf("Read returned %d bytes, want %d", n, len(b))
	}

	// ca34: extension type, 0002: extension data length, 0000: empty list.
	if got, want := hex.EncodeToString(b), "ca3400020000"; got != want {
		t.Errorf("wire bytes = %s, want %s", got, want)
	}
}

// TestTrustAnchorsWireFormat checks a non-empty list. Each identifier carries a one
// byte length prefix, inside a two byte list, inside the extension data.
func TestTrustAnchorsWireFormat(t *testing.T) {
	ext := &TrustAnchorsExtension{TrustAnchors: [][]byte{
		{0x01, 0x02, 0x03},
		{0xff},
	}}

	// 4 header + 2 list length + (1+3) + (1+1)
	if got, want := ext.Len(), 12; got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}

	b := make([]byte, ext.Len())
	if _, err := ext.Read(b); err != io.EOF {
		t.Fatalf("Read: %v, want io.EOF", err)
	}

	want := "ca34" + "0008" + "0006" + "03010203" + "01ff"
	if got := hex.EncodeToString(b); got != want {
		t.Errorf("wire bytes = %s, want %s", got, want)
	}
}

// TestTrustAnchorsShortBuffer checks that Read refuses a buffer it would overrun.
func TestTrustAnchorsShortBuffer(t *testing.T) {
	ext := &TrustAnchorsExtension{}
	if _, err := ext.Read(make([]byte, ext.Len()-1)); !errors.Is(err, io.ErrShortBuffer) {
		t.Errorf("Read into a short buffer: %v, want io.ErrShortBuffer", err)
	}
}

// TestTrustAnchorsRejectsBadIdentifiers checks the two identifier lengths that the
// peer would reject, so a caller finds out locally instead of on the wire.
func TestTrustAnchorsRejectsBadIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   []byte
	}{
		{"empty", []byte{}},
		{"too long", make([]byte, 256)},
	} {
		ext := &TrustAnchorsExtension{TrustAnchors: [][]byte{tc.id}}
		if _, err := ext.Read(make([]byte, ext.Len())); err == nil || err == io.EOF {
			t.Errorf("Read with an %s identifier: %v, want an error", tc.name, err)
		}
	}
}

// TestTrustAnchorsRoundTrip checks that Write parses back what Read produced, which is
// what the fingerprinter relies on.
func TestTrustAnchorsRoundTrip(t *testing.T) {
	for _, anchors := range [][][]byte{
		nil,
		{{0x01}},
		{{0x01, 0x02, 0x03}, {0xff}, bytes.Repeat([]byte{0xab}, 255)},
	} {
		ext := &TrustAnchorsExtension{TrustAnchors: anchors}
		b := make([]byte, ext.Len())
		if _, err := ext.Read(b); err != io.EOF {
			t.Fatalf("Read: %v", err)
		}

		// Write consumes the extension data, without the four byte header.
		parsed := &TrustAnchorsExtension{}
		n, err := parsed.Write(b[4:])
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if n != len(b)-4 {
			t.Errorf("Write consumed %d bytes, want %d", n, len(b)-4)
		}
		if len(parsed.TrustAnchors) != len(anchors) {
			t.Fatalf("round trip produced %d identifiers, want %d", len(parsed.TrustAnchors), len(anchors))
		}
		for i := range anchors {
			if !bytes.Equal(parsed.TrustAnchors[i], anchors[i]) {
				t.Errorf("identifier %d = %x, want %x", i, parsed.TrustAnchors[i], anchors[i])
			}
		}
	}
}

// TestTrustAnchorsWriteDoesNotAliasInput checks that Write copies out of the caller's
// buffer. ReadTLSExtensions hands it a slice of the ClientHello, which is reused.
func TestTrustAnchorsWriteDoesNotAliasInput(t *testing.T) {
	data := []byte{0x00, 0x04, 0x03, 0x01, 0x02, 0x03}
	ext := &TrustAnchorsExtension{}
	if _, err := ext.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	clobbered := slices.Clone(ext.TrustAnchors[0])
	for i := range data {
		data[i] = 0xff
	}
	if !bytes.Equal(ext.TrustAnchors[0], clobbered) {
		t.Errorf("identifier changed to %x after the input was overwritten, want %x",
			ext.TrustAnchors[0], clobbered)
	}
}

// TestTrustAnchorsWriteRejectsMalformed checks the decode errors that BoringSSL also
// rejects in ssl_is_valid_trust_anchor_list.
func TestTrustAnchorsWriteRejectsMalformed(t *testing.T) {
	for name, data := range map[string][]byte{
		"missing list length":  {0x00},
		"list length overruns": {0x00, 0x08, 0x01, 0x02},
		"zero length id":       {0x00, 0x01, 0x00},
		"id overruns list":     {0x00, 0x02, 0x05, 0x01},
	} {
		ext := &TrustAnchorsExtension{}
		if _, err := ext.Write(data); err == nil {
			t.Errorf("%s: Write accepted %x, want an error", name, data)
		}
	}
}

// TestTrustAnchorsFromID checks that the extension is reachable by codepoint, which is
// what the fingerprinter and the JSON ClientHello parser use.
func TestTrustAnchorsFromID(t *testing.T) {
	ext := ExtensionFromID(utlsExtensionTrustAnchors)
	if ext == nil {
		t.Fatal("ExtensionFromID returned nil for trust_anchors")
	}
	if _, ok := ext.(*TrustAnchorsExtension); !ok {
		t.Errorf("ExtensionFromID returned %T, want *TrustAnchorsExtension", ext)
	}
	if _, ok := ext.(TLSExtensionWriter); !ok {
		t.Error("TrustAnchorsExtension does not implement TLSExtensionWriter")
	}
}

// TestTrustAnchorsFingerprintRoundTrip runs the extension through ReadTLSExtensions,
// the path the Fingerprinter uses, and checks it comes back as a typed extension
// rather than a GenericExtension.
func TestTrustAnchorsFingerprintRoundTrip(t *testing.T) {
	raw, err := hex.DecodeString("ca340008000603010203" + "01ff")
	if err != nil {
		t.Fatal(err)
	}

	spec := &ClientHelloSpec{}
	if err := spec.ReadTLSExtensions(raw, false, false); err != nil {
		t.Fatalf("ReadTLSExtensions: %v", err)
	}
	if len(spec.Extensions) != 1 {
		t.Fatalf("parsed %d extensions, want 1", len(spec.Extensions))
	}
	ext, ok := spec.Extensions[0].(*TrustAnchorsExtension)
	if !ok {
		t.Fatalf("parsed extension is %T, want *TrustAnchorsExtension", spec.Extensions[0])
	}
	if len(ext.TrustAnchors) != 2 {
		t.Fatalf("parsed %d identifiers, want 2", len(ext.TrustAnchors))
	}
	if !bytes.Equal(ext.TrustAnchors[0], []byte{0x01, 0x02, 0x03}) {
		t.Errorf("identifier 0 = %x, want 010203", ext.TrustAnchors[0])
	}
}

// TestTrustAnchorsJSON checks the JSON ClientHello form. Identifiers are opaque bytes,
// so encoding/json renders them base64, matching CookieExtension and friends.
func TestTrustAnchorsJSON(t *testing.T) {
	var unmarshaler TLSExtensionsJSONUnmarshaler
	// AQID is base64 for 010203.
	input := `[{"name": "trust_anchors", "trust_anchors": ["AQID"]}]`
	if err := json.Unmarshal([]byte(input), &unmarshaler); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	exts := unmarshaler.Extensions()
	if len(exts) != 1 {
		t.Fatalf("parsed %d extensions, want 1", len(exts))
	}
	ext, ok := exts[0].(*TrustAnchorsExtension)
	if !ok {
		t.Fatalf("parsed extension is %T, want *TrustAnchorsExtension", exts[0])
	}
	if len(ext.TrustAnchors) != 1 || !bytes.Equal(ext.TrustAnchors[0], []byte{0x01, 0x02, 0x03}) {
		t.Errorf("identifiers = %x, want [010203]", ext.TrustAnchors)
	}
}
