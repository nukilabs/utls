package tls

import (
	"crypto/mldsa"
	"crypto/rand"
	ctls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"
)

// TestMLDSASignatureSchemeValues checks the codepoints of the ML-DSA schemes against
// RFC 9881, and checks that the deprecated Fake* names still resolve to them.
func TestMLDSASignatureSchemeValues(t *testing.T) {
	for _, tc := range []struct {
		scheme SignatureScheme
		alias  SignatureScheme
		want   uint16
	}{
		{MLDSA44, FakeMLDSA44, 0x0904},
		{MLDSA65, FakeMLDSA65, 0x0905},
		{MLDSA87, FakeMLDSA87, 0x0906},
	} {
		if uint16(tc.scheme) != tc.want {
			t.Errorf("%v = 0x%04x, want 0x%04x", tc.scheme, uint16(tc.scheme), tc.want)
		}
		if tc.alias != tc.scheme {
			t.Errorf("deprecated alias = 0x%04x, want 0x%04x", uint16(tc.alias), tc.want)
		}
	}
}

// TestMLDSASignatureSchemeString checks the generated stringer entries.
func TestMLDSASignatureSchemeString(t *testing.T) {
	for _, tc := range []struct {
		scheme SignatureScheme
		want   string
	}{
		{MLDSA44, "MLDSA44"},
		{MLDSA65, "MLDSA65"},
		{MLDSA87, "MLDSA87"},
	} {
		if got := tc.scheme.String(); got != tc.want {
			t.Errorf("SignatureScheme(0x%04x).String() = %q, want %q", uint16(tc.scheme), got, tc.want)
		}
	}
}

// TestTypeAndHashFromMLDSAScheme checks that the ML-DSA schemes map to the ML-DSA
// signature type and use no pre-hash.
func TestTypeAndHashFromMLDSAScheme(t *testing.T) {
	for _, scheme := range []SignatureScheme{MLDSA44, MLDSA65, MLDSA87} {
		sigType, hash, err := typeAndHashFromSignatureScheme(scheme)
		if err != nil {
			t.Errorf("typeAndHashFromSignatureScheme(%v): %v", scheme, err)
			continue
		}
		if sigType != signatureMLDSA {
			t.Errorf("%v maps to signature type %d, want signatureMLDSA (%d)", scheme, sigType, signatureMLDSA)
		}
		if hash != directSigning {
			t.Errorf("%v maps to hash %v, want directSigning", scheme, hash)
		}
	}
}

// TestVerifyMLDSAHandshakeSignature signs a message with an ML-DSA key and verifies it
// through the handshake code. It covers the signature step only, without a certificate.
func TestVerifyMLDSAHandshakeSignature(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey: %v", err)
	}

	signed := []byte("the transcript that the CertificateVerify message signs")
	signature, err := key.Sign(rand.Reader, signed, &mldsa.Options{})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := verifyHandshakeSignature(signatureMLDSA, key.PublicKey(), directSigning, signed, signature); err != nil {
		t.Errorf("a correct signature does not verify: %v", err)
	}

	signed[0] ^= 0xff
	if err := verifyHandshakeSignature(signatureMLDSA, key.PublicKey(), directSigning, signed, signature); err == nil {
		t.Error("a signature over different data verifies, want an error")
	}
}

// TestClientSupportedSignatureAlgorithms checks that a client accepts the ML-DSA schemes
// for TLS 1.3 only, since the codepoints are defined for TLS 1.3 only.
func TestClientSupportedSignatureAlgorithms(t *testing.T) {
	tls13 := clientSupportedSignatureAlgorithms(VersionTLS13)
	tls12 := clientSupportedSignatureAlgorithms(VersionTLS12)
	for _, scheme := range []SignatureScheme{MLDSA44, MLDSA65, MLDSA87} {
		if !slices.Contains(tls13, scheme) {
			t.Errorf("the TLS 1.3 client list is missing %v", scheme)
		}
		if slices.Contains(tls12, scheme) {
			t.Errorf("the TLS 1.2 client list holds %v, but ML-DSA requires TLS 1.3", scheme)
		}
	}
}

// TestSharedListHoldsNoMLDSA checks the shared list that the server call sites read. A
// uTLS server must not advertise the ML-DSA codepoints in its CertificateRequest, and
// the default ClientHello must not carry them either, so HelloGolang keeps its
// fingerprint. This test fails if a later change puts ML-DSA in the shared list.
func TestSharedListHoldsNoMLDSA(t *testing.T) {
	before := slices.Clone(supportedSignatureAlgorithms())

	// An append to the shared list could write into the array behind
	// defaultSupportedSignatureAlgorithms.
	clientSupportedSignatureAlgorithms(VersionTLS13)

	after := supportedSignatureAlgorithms()
	if !slices.Equal(before, after) {
		t.Errorf("clientSupportedSignatureAlgorithms mutated the shared list: %v became %v", before, after)
	}
	for _, scheme := range []SignatureScheme{MLDSA44, MLDSA65, MLDSA87} {
		if slices.Contains(after, scheme) {
			t.Errorf("supportedSignatureAlgorithms holds %v, so a server would advertise it", scheme)
		}
	}
}

// TestChrome150AdvertisesMLDSA checks that the Chrome 150 profiles carry the ML-DSA
// codepoints in their signature_algorithms extension, and that Chrome 133 does not.
// Without a profile that advertises them, a server never selects ML-DSA.
func TestChrome150AdvertisesMLDSA(t *testing.T) {
	for _, tc := range []struct {
		id   ClientHelloID
		want bool
	}{
		{HelloChrome_150, true},
		{HelloChrome_150_PSK, true},
		{HelloChrome_133, false},
	} {
		spec, err := utlsIdToSpec(tc.id)
		if err != nil {
			t.Errorf("utlsIdToSpec(%s): %v", tc.id.Str(), err)
			continue
		}
		var sigAlgs []SignatureScheme
		for _, ext := range spec.Extensions {
			if e, ok := ext.(*SignatureAlgorithmsExtension); ok {
				sigAlgs = e.SupportedSignatureAlgorithms
			}
		}
		if len(sigAlgs) == 0 {
			t.Errorf("%s carries no signature_algorithms extension", tc.id.Str())
			continue
		}
		for _, scheme := range []SignatureScheme{MLDSA44, MLDSA65, MLDSA87} {
			if got := slices.Contains(sigAlgs, scheme); got != tc.want {
				t.Errorf("%s advertises %v = %v, want %v", tc.id.Str(), scheme, got, tc.want)
			}
		}
	}
}

// TestChromeAutoIsChrome150 checks that HelloChrome_Auto tracks the newest Chrome
// profile, which is the convention for the Auto identifiers.
func TestChromeAutoIsChrome150(t *testing.T) {
	if HelloChrome_Auto != HelloChrome_150 {
		t.Errorf("HelloChrome_Auto = %s, want %s", HelloChrome_Auto.Str(), HelloChrome_150.Str())
	}
}

// TestChrome150PSKCarriesPreSharedKey checks that the PSK variant ends with the
// pre_shared_key extension, which RFC 8446 requires to be last.
func TestChrome150PSKCarriesPreSharedKey(t *testing.T) {
	spec, err := utlsIdToSpec(HelloChrome_150_PSK)
	if err != nil {
		t.Fatalf("utlsIdToSpec: %v", err)
	}
	last := spec.Extensions[len(spec.Extensions)-1]
	if _, ok := last.(*UtlsPreSharedKeyExtension); !ok {
		t.Errorf("the last extension is %T, want *UtlsPreSharedKeyExtension", last)
	}
}

// mldsaCertificate returns a self-signed ML-DSA certificate and its key.
func mldsaCertificate(t *testing.T) ([]byte, *mldsa.PrivateKey) {
	t.Helper()

	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mldsa.example"},
		DNSNames:              []string{"mldsa.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.PublicKey(), key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	return der, key
}

// TestClientVerifiesMLDSAServerCertificate runs a full TLS 1.3 handshake against a
// standard library server that holds an ML-DSA certificate. The uTLS client has to
// verify the CertificateVerify message of the server and the chain.
//
// The server is the standard library, because a uTLS server does not offer ML-DSA.
func TestClientVerifiesMLDSAServerCertificate(t *testing.T) {
	der, key := mldsaCertificate(t)
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	listener := newLocalListener(t)
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverConn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer serverConn.Close()

		server := ctls.Server(serverConn, &ctls.Config{
			Certificates: []ctls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			MinVersion:   ctls.VersionTLS13,
		})
		serverErr <- server.Handshake()
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	client := UClient(clientConn, &Config{
		ServerName: "mldsa.example",
		RootCAs:    roots,
	}, HelloChrome_150)
	if err := client.Handshake(); err != nil {
		t.Fatalf("the client handshake failed: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("the server handshake failed: %v", err)
	}

	state := client.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("the connection holds no peer certificate")
	}
	if got := state.PeerCertificates[0].SignatureAlgorithm; got != x509.MLDSA65 {
		t.Errorf("the certificate uses %v, want MLDSA65", got)
	}
}

// TestMLDSARequiresTLS13 checks that an ML-DSA certificate is refused below TLS 1.3,
// where the codepoints are not defined.
func TestMLDSARequiresTLS13(t *testing.T) {
	der, key := mldsaCertificate(t)

	// signatureSchemesForCertificate must offer ML-DSA for TLS 1.3 only.
	cert := &Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	if got := signatureSchemesForCertificate(VersionTLS13, cert); !slices.Equal(got, []SignatureScheme{MLDSA65}) {
		t.Errorf("signatureSchemesForCertificate(TLS 1.3) = %v, want [MLDSA65]", got)
	}
	if got := signatureSchemesForCertificate(VersionTLS12, cert); len(got) != 0 {
		t.Errorf("signatureSchemesForCertificate(TLS 1.2) = %v, want none", got)
	}

	// legacyTypeAndHashFromPublicKey covers TLS 1.0 and 1.1.
	if _, _, err := legacyTypeAndHashFromPublicKey(key.PublicKey()); err == nil {
		t.Error("legacyTypeAndHashFromPublicKey accepts an ML-DSA key, want an error")
	}
}
